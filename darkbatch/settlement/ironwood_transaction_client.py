"""
Local client for the official Rust Ironwood v6 transaction builder.

This code must run in a trusted local wallet process, not in the public coordinator:
the JSON input includes private spending keys. It does not invent notes or witnesses;
the caller must supply them from a real Ironwood-capable wallet and matching Zebra tree state.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import subprocess
from typing import Any, Mapping


VERSION_GROUP_ID = 0xD884B698
IRONWOOD_NU6_3_BRANCH_ID = 0x37A5165B
IRONWOOD_NU7_BRANCH_ID = 0x77190AD9
TX_VERSION_V6 = 0x80000006


@dataclass(frozen=True)
class BuiltIronwoodTransaction:
    txid: str
    raw_tx_hex: str
    raw_tx_bytes_len: int
    target_height: int
    consensus_branch_id: int
    version_group_id: int
    transaction_version: int
    network: str = "testnet"
    broadcast: bool = False

    @property
    def raw_tx_bytes(self) -> bytes:
        return bytes.fromhex(self.raw_tx_hex)


def _default_binary_path() -> str:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    name = "darkbatch_crypto.exe" if os.name == "nt" else "darkbatch_crypto"
    release = os.path.join(root, "darkbatch_crypto", "target", "release", name)
    debug = os.path.join(root, "darkbatch_crypto", "target", "debug", name)
    return release if os.path.isfile(release) else debug


def _validate_result(data: Mapping[str, Any]) -> BuiltIronwoodTransaction:
    if data.get("status") != "BUILT_NOT_BROADCAST" or data.get("broadcast") is not False:
        raise RuntimeError("Rust builder returned an unexpected state; refusing to use the result.")
    if data.get("consensus_ready") is not True:
        raise RuntimeError("Rust builder did not assert a completed official transaction.")
    if data.get("network") != "testnet":
        raise RuntimeError("Only Testnet transactions are enabled by this client.")

    txid = str(data.get("txid", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise RuntimeError("Rust builder returned an invalid txid.")
    raw_hex = str(data.get("raw_tx_hex", ""))
    if not raw_hex or len(raw_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise RuntimeError("Rust builder returned invalid raw transaction hexadecimal.")
    raw = bytes.fromhex(raw_hex)
    declared_length = data.get("raw_tx_bytes_len")
    if not isinstance(declared_length, int) or declared_length != len(raw):
        raise RuntimeError("Rust builder raw transaction length does not match the declared length.")
    if len(raw) < 12:
        raise RuntimeError("Rust builder returned a truncated transaction.")
    header = int.from_bytes(raw[:4], "little")
    version_group_id = int.from_bytes(raw[4:8], "little")
    branch_id = int.from_bytes(raw[8:12], "little")
    if header != TX_VERSION_V6:
        raise RuntimeError("Official builder output is not a version 6 transaction.")
    if version_group_id != VERSION_GROUP_ID:
        raise RuntimeError("Official builder output has an unexpected version-group ID.")
    if branch_id not in {IRONWOOD_NU6_3_BRANCH_ID, IRONWOOD_NU7_BRANCH_ID}:
        raise RuntimeError("Official builder output has an unsupported Ironwood consensus branch.")
    if int(data.get("consensus_branch_id", -1), 0) != branch_id:
        # Rust CLI formats this field as 0x-prefixed hex.
        raise RuntimeError("Builder result branch ID disagrees with its serialized transaction.")
    if int(data.get("version_group_id", -1), 0) != version_group_id:
        raise RuntimeError("Builder result version-group ID disagrees with its serialized transaction.")
    if data.get("transaction_version") != 6:
        raise RuntimeError("Builder result version metadata is not v6.")

    return BuiltIronwoodTransaction(
        txid=txid,
        raw_tx_hex=raw_hex.lower(),
        raw_tx_bytes_len=len(raw),
        target_height=int(data["target_height"]),
        consensus_branch_id=branch_id,
        version_group_id=version_group_id,
        transaction_version=6,
    )



def inspect_raw_ironwood_transaction(
    raw_tx_hex: str,
    *,
    binary_path: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """
    Ask the official Rust/Zcash decoder to parse raw bytes and calculate the txid
    before broadcast. This protects the caller from a txid/raw-bytes mismatch.
    """
    raw_hex = (raw_tx_hex or "").strip()
    if not raw_hex or len(raw_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise RuntimeError("Raw transaction must be non-empty even-length hexadecimal.")

    binary = binary_path or _default_binary_path()
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Official Rust transaction decoder not found or not executable: {binary}")

    payload = json.dumps({
        "network": "testnet",
        "raw_tx_hex": raw_hex.lower(),
    }, separators=(",", ":"), ensure_ascii=True)
    try:
        completed = subprocess.run(
            [binary, "inspect-ironwood-transaction-stdin"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Official transaction decoder could not complete: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.strip() or f"Rust decoder exited with code {completed.returncode}."
        raise RuntimeError(f"Official transaction decoder rejected the raw transaction: {reason}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Official transaction decoder returned malformed JSON.") from exc

    if not isinstance(result, dict) or result.get("status") != "PARSED_V6_TRANSACTION":
        raise RuntimeError("Official transaction decoder returned an unexpected status.")
    txid = str(result.get("txid", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise RuntimeError("Official transaction decoder returned an invalid transaction ID.")
    raw = bytes.fromhex(raw_hex)
    if result.get("network") != "testnet" or result.get("raw_tx_bytes_len") != len(raw):
        raise RuntimeError("Official transaction decoder metadata does not match the supplied bytes.")
    if result.get("header") != "0x80000006" or result.get("version_group_id") != "0xd884b698":
        raise RuntimeError("Official transaction decoder did not confirm the expected v6 header.")
    if result.get("consensus_branch_id") not in {"0x37a5165b", "0x77190ad9"}:
        raise RuntimeError("Official transaction decoder returned an unsupported Ironwood branch.")
    return result


def build_ironwood_transaction(
    request: Mapping[str, Any],
    *,
    binary_path: str | None = None,
    timeout_seconds: int = 1800,
) -> BuiltIronwoodTransaction:
    """
    Build a real v6 transaction locally from real spend notes, private keys and witnesses.

    Never call this from the public coordinator/API. Use it inside a trusted wallet
    process and pass only the resulting signed raw transaction to the coordinator.
    """
    binary = binary_path or _default_binary_path()
    if not os.path.isfile(binary):
        raise RuntimeError(
            f"DarkBatch Rust engine not found at {binary}; run "
            "'cargo build --manifest-path darkbatch_crypto/Cargo.toml --release'."
        )
    if not os.access(binary, os.X_OK):
        raise RuntimeError(f"Rust engine is not executable: {binary}")

    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True)
    try:
        completed = subprocess.run(
            [binary, "build-ironwood-transaction-stdin"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Official Ironwood builder timed out; no transaction was accepted or broadcast.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not start the official Rust transaction builder: {exc}") from exc

    if completed.returncode != 0:
        # stderr contains error details but never the JSON request or private keys.
        reason = completed.stderr.strip() or f"Rust builder exited with code {completed.returncode}."
        raise RuntimeError(f"Ironwood transaction build failed closed: {reason}")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Rust builder returned malformed JSON; transaction result discarded.") from exc
    if not isinstance(response, dict):
        raise RuntimeError("Rust builder response must be a JSON object.")
    return _validate_result(response)
