"""
DarkBatch Real PCZT Settlement Orchestrator
============================================
Drives the official Rust CLI for real Zcash v6 transaction construction:

  1. build-fba-pczt-local  (zcash_primitives Builder → unsigned PCZT)
  2. sign-pczt-local        (SpendAuth signature per participant)
  3. combine-pczts-local    (Combiner: merge base + signed contributions)
  4. prove-extract-pczt-local (Halo 2 proof via orchard::circuit + TX extraction)
  5. sendrawtransaction     (broadcast to Zebra testnet)

Nothing in this module is simulated. If any step fails the settlement is aborted.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# ── Binary path ────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent.parent.parent
_CRYPTO_BIN = (
    _HERE / "darkbatch_crypto" / "target" / "release" / "darkbatch_crypto"
)
# Also check .exe for Windows
if not _CRYPTO_BIN.exists():
    _CRYPTO_BIN_EXE = _CRYPTO_BIN.with_suffix(".exe")
    if _CRYPTO_BIN_EXE.exists():
        _CRYPTO_BIN = _CRYPTO_BIN_EXE


def _bin() -> str:
    if not _CRYPTO_BIN.exists():
        raise RuntimeError(
            f"darkbatch_crypto binary not found at {_CRYPTO_BIN}. "
            "Run: cargo build --release --manifest-path darkbatch_crypto/Cargo.toml"
        )
    return str(_CRYPTO_BIN)


def _run(args: List[str], input_data: Optional[bytes] = None, timeout: int = 120) -> bytes:
    """Run darkbatch_crypto CLI, return stdout bytes. Raises on failure."""
    cmd = [_bin()] + args
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        raise RuntimeError(f"darkbatch_crypto {args[0]} failed: {stderr}")
    return result.stdout


# ── Workdir helper ──────────────────────────────────────────────────────────────
class _TmpWorkdir:
    """Creates a secure tempdir for private PCZT files, cleans up on exit."""

    def __enter__(self):
        self._dir = tempfile.mkdtemp(prefix="darkbatch_pczt_")
        os.chmod(self._dir, 0o700)
        return Path(self._dir)

    def __exit__(self, *_):
        import shutil
        try:
            shutil.rmtree(self._dir, ignore_errors=True)
        except Exception:
            pass


# ── RPC helpers ────────────────────────────────────────────────────────────────
async def _rpc(session: aiohttp.ClientSession, url: str, method: str, params: list) -> Any:
    payload = {"jsonrpc": "1.0", "id": "darkbatch", "method": method, "params": params}
    async with session.post(url, json=payload) as resp:
        data = await resp.json(content_type=None)
    if data.get("error"):
        raise RuntimeError(f"RPC {method} error: {data['error']}")
    return data["result"]


# ── Main orchestrator ───────────────────────────────────────────────────────────
class RealPCZTSettlement:
    """
    Drives a complete real Zcash v6 settlement using the official Rust PCZT workflow.

    Required env vars:
      ZCASH_TESTNET_RPC_URL   e.g. http://127.0.0.1:18232
      ZCASH_TESTNET_RPC_USER
      ZCASH_TESTNET_RPC_PASS

    Required files per participant (set via participant_key_files):
      A JSON file containing {"sk_hex": "<64-hex SpendingKey>"} for each spend input.
      NEVER pass raw keys via API. These files must be on the local trusted machine only.
    """

    def __init__(
        self,
        rpc_url: str = "",
        rpc_user: str = "",
        rpc_password: str = "",
    ):
        self.rpc_url = rpc_url or os.environ.get("ZCASH_TESTNET_RPC_URL", "http://127.0.0.1:18232")
        self.rpc_user = rpc_user or os.environ.get("ZCASH_TESTNET_RPC_USER", "")
        self.rpc_pass = rpc_password or os.environ.get("ZCASH_TESTNET_RPC_PASS", "")
        self._auth = aiohttp.BasicAuth(self.rpc_user, self.rpc_pass) if self.rpc_user else None

    # ── Step 1: Build unsigned PCZT from FBA settlement plan ────────────────────
    async def build_fba_pczt(
        self,
        settlement_json: Dict[str, Any],
        workdir: Path,
    ) -> tuple[bytes, Dict[str, Any]]:
        """
        Call `build-fba-pczt-local` with the settlement plan.
        Returns (pczt_bytes, build_report).
        """
        build_input_path = workdir / "private_fba_settlement.json"
        pczt_output_path = workdir / "unsigned.pczt"
        report_output_path = workdir / "build_report.json"

        # Write the settlement JSON to a private file
        build_input_path.write_text(json.dumps(settlement_json), encoding="utf-8")
        os.chmod(build_input_path, 0o600)

        stdout = _run([
            "build-fba-pczt-local",
            str(build_input_path),
            str(pczt_output_path),
            str(report_output_path),
        ], timeout=60)

        report = json.loads(report_output_path.read_text(encoding="utf-8"))
        pczt_bytes = pczt_output_path.read_bytes()

        logger.info(
            "PCZT built: %d inputs, %d recipients, anchor=%s",
            report.get("input_count"), report.get("recipient_output_count"),
            report.get("ironwood_anchor_hex", "")[:16],
        )
        return pczt_bytes, report

    # ── Step 2 & 3: Sign per participant + combine ──────────────────────────────
    async def sign_and_combine(
        self,
        pczt_bytes: bytes,
        spend_action_indexes: List[int],
        participant_key_files: List[str],
        workdir: Path,
    ) -> bytes:
        """
        For each spend action, redact the PCZT for that participant,
        sign with their local key file, then combine all contributions.
        Returns the combined signed PCZT bytes.
        """
        base_pczt_path = workdir / "unsigned.pczt"
        base_pczt_path.write_bytes(pczt_bytes)
        os.chmod(base_pczt_path, 0o600)

        signed_paths = []

        for i, (action_idx, key_file) in enumerate(
            zip(spend_action_indexes, participant_key_files)
        ):
            if not os.path.isfile(key_file):
                raise FileNotFoundError(
                    f"Participant key file not found: {key_file}\n"
                    "Each participant must provide their SpendingKey file locally."
                )

            # Redact for this participant
            redacted_path = workdir / f"redacted_{i}.pczt"
            _run([
                "redact-pczt-local",
                str(base_pczt_path),
                str(action_idx),
                str(redacted_path),
            ])

            # Sign with participant's key
            signed_path = workdir / f"signed_{i}.pczt"
            _run([
                "sign-pczt-local",
                str(redacted_path),
                key_file,
                str(action_idx),
                str(signed_path),
            ])
            signed_paths.append(signed_path)
            logger.info("Participant %d signed action %d", i, action_idx)

        # Combine: base PCZT + all signed contributions
        combined_path = workdir / "combined_signed.pczt"
        combine_args = ["combine-pczts-local", str(combined_path), str(base_pczt_path)]
        combine_args += [str(p) for p in signed_paths]
        _run(combine_args)

        combined_bytes = combined_path.read_bytes()
        logger.info("PCZT contributions combined: %d bytes", len(combined_bytes))
        return combined_bytes

    # ── Step 4: Generate Halo 2 proof + extract TX ─────────────────────────────
    async def prove_and_extract(
        self,
        signed_pczt_bytes: bytes,
        workdir: Path,
    ) -> tuple[str, str, Dict[str, Any]]:
        """
        Call `prove-extract-pczt-local` — runs orchard::circuit::Prover
        which generates a real Halo 2 proof (~3-10 seconds).
        Returns (txid, raw_tx_hex, proof_report).
        """
        signed_pczt_path = workdir / "combined_signed.pczt"
        signed_pczt_path.write_bytes(signed_pczt_bytes)
        os.chmod(signed_pczt_path, 0o600)

        tx_hex_path = workdir / "raw_transaction.hex"
        report_path = workdir / "proof_report.json"

        logger.info("Generating Halo 2 proof via orchard::circuit (this takes 3-10s)...")
        t0 = time.monotonic()

        _run([
            "prove-extract-pczt-local",
            str(signed_pczt_path),
            str(tx_hex_path),
            str(report_path),
        ], timeout=300)  # proof can take up to 5 min on slow hardware

        elapsed = time.monotonic() - t0
        raw_tx_hex = tx_hex_path.read_text(encoding="utf-8").strip()
        report = json.loads(report_path.read_text(encoding="utf-8"))

        txid = report.get("txid", "")
        logger.info(
            "Halo 2 proof complete in %.1fs — TXID: %s, TX size: %d bytes",
            elapsed, txid, len(raw_tx_hex) // 2,
        )
        return txid, raw_tx_hex, report

    # ── Step 5: Broadcast to Zebra ──────────────────────────────────────────────
    async def broadcast(self, raw_tx_hex: str) -> str:
        """Send raw tx to zebrad via sendrawtransaction. Returns txid."""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(auth=self._auth, connector=connector) as session:
            txid = await _rpc(session, self.rpc_url, "sendrawtransaction", [raw_tx_hex])
        logger.info("Broadcast accepted by Zebra — TXID: %s", txid)
        return txid

    async def wait_for_confirmation(
        self, txid: str, min_confirmations: int = 1, timeout_sec: int = 600
    ) -> Dict[str, Any]:
        """Poll gettransaction until confirmed."""
        connector = aiohttp.TCPConnector(ssl=False)
        deadline = time.monotonic() + timeout_sec
        async with aiohttp.ClientSession(auth=self._auth, connector=connector) as session:
            while time.monotonic() < deadline:
                try:
                    tx = await _rpc(session, self.rpc_url, "getrawtransaction", [txid, 1])
                    confs = tx.get("confirmations", 0)
                    if confs >= min_confirmations:
                        return {
                            "txid": txid,
                            "confirmations": confs,
                            "block_hash": tx.get("blockhash"),
                            "block_height": tx.get("blockheight"),
                            "status": "CONFIRMED",
                        }
                except Exception:
                    pass
                await asyncio.sleep(30)  # Ironwood: 25s blocks
        raise TimeoutError(f"TX {txid} not confirmed within {timeout_sec}s")

    # ── Full settlement pipeline ────────────────────────────────────────────────
    async def settle(
        self,
        fba_settlement_json: Dict[str, Any],
        participant_key_files: List[str],
    ) -> Dict[str, Any]:
        """
        Complete real Zcash v6 settlement:
          build → sign → combine → prove → broadcast → confirm

        fba_settlement_json: the PcztBuildRequest JSON matching Rust's struct.
        participant_key_files: list of paths to {"sk_hex":"..."} files,
                               one per spend input, in the same order as inputs.

        Returns settlement receipt with real TXID.
        """
        with _TmpWorkdir() as workdir:
            # 1. Build
            pczt_bytes, build_report = await self.build_fba_pczt(
                fba_settlement_json, workdir
            )
            spend_indexes = build_report.get("ironwood_spend_action_indexes", [])

            if len(participant_key_files) != len(spend_indexes):
                raise ValueError(
                    f"Need {len(spend_indexes)} participant key files "
                    f"(one per spend action), got {len(participant_key_files)}"
                )

            # 2 & 3. Sign + combine
            signed_pczt = await self.sign_and_combine(
                pczt_bytes, spend_indexes, participant_key_files, workdir
            )

            # 4. Halo 2 proof + TX extraction
            txid, raw_tx_hex, proof_report = await self.prove_and_extract(
                signed_pczt, workdir
            )

            # 5. Broadcast
            broadcast_txid = await self.broadcast(raw_tx_hex)
            if broadcast_txid != txid:
                logger.warning(
                    "Zebra returned txid %s, local extraction had %s",
                    broadcast_txid, txid,
                )
                txid = broadcast_txid

            # 6. Wait for confirmation
            confirmation = await self.wait_for_confirmation(txid)

        return {
            "status": "SETTLED_ON_TESTNET",
            "txid": txid,
            "block_hash": confirmation.get("block_hash"),
            "block_height": confirmation.get("block_height"),
            "confirmations": confirmation.get("confirmations"),
            "proof_report": proof_report,
            "build_report": build_report,
            "network": "Zcash Testnet",
            "transaction_version": 6,
            "simulation": False,
        }


# ── CLI wrapper for standalone use ─────────────────────────────────────────────
async def _cli_main():
    import sys
    if len(sys.argv) < 3:
        print(
            "Usage: python -m darkbatch.settlement.real_pczt_settlement "
            "<fba_settlement.json> <key_file_1> [key_file_2 ...]"
        )
        sys.exit(1)

    settlement_path = sys.argv[1]
    key_files = sys.argv[2:]

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    with open(settlement_path, encoding="utf-8") as f:
        settlement_json = json.load(f)

    orchestrator = RealPCZTSettlement()
    result = await orchestrator.settle(settlement_json, key_files)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(_cli_main())
