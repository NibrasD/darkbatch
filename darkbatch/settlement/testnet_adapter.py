"""
Ironwood Testnet broadcast adapter.

This adapter intentionally has no simulator fallback. A local model is not Zebra,
and a mempool acceptance is not a block confirmation. Only a transaction produced
by the authoritative Ironwood builder may be submitted to a real Testnet node.
"""
import os
import json
import logging
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from darkbatch.settlement.v6_bundle import SettlementBundle

logger = logging.getLogger("darkbatch.settlement.adapter")
IRONWOOD_TESTNET_ACTIVATION_HEIGHT = 4_134_000


class TestnetSettlementAdapter:
    def __init__(
        self,
        node_simulator=None,  # Accepted for old call sites; never used to validate/broadcast.
        rpc_url: Optional[str] = None,
        rpc_user: Optional[str] = None,
        rpc_password: Optional[str] = None,
    ):
        # No implicit localhost/default-node broadcast. Configure the intended testnet explicitly.
        self.rpc_url = (rpc_url or os.getenv("ZCASH_TESTNET_RPC_URL") or "").strip()
        self.rpc_user = rpc_user if rpc_user is not None else os.getenv("ZCASH_TESTNET_RPC_USER", "")
        self.rpc_password = rpc_password if rpc_password is not None else os.getenv("ZCASH_TESTNET_RPC_PASS", "")
        self.broadcast_history: Dict[str, Dict[str, Any]] = {}

    def _rpc(self, method: str, params=None, timeout: float = 3.0) -> Dict[str, Any]:
        if not self.rpc_url:
            raise RuntimeError("ZCASH_TESTNET_RPC_URL is not configured.")
        payload = {
            "jsonrpc": "1.0",
            "id": "darkbatch_ironwood",
            "method": method,
            "params": params or [],
        }
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.rpc_user and self.rpc_password:
            import base64
            token = base64.b64encode(
                f"{self.rpc_user}:{self.rpc_password}".encode("utf-8")
            ).decode("ascii")
            req.add_header("Authorization", f"Basic {token}")

        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload_out = json.loads(response.read().decode("utf-8"))
        if payload_out.get("error"):
            raise RuntimeError(f"Zebra RPC {method} failed: {payload_out['error']}")
        if "result" not in payload_out:
            raise RuntimeError(f"Zebra RPC {method} returned no result.")
        result = payload_out["result"]
        if not isinstance(result, dict) and method != "sendrawtransaction":
            raise RuntimeError(f"Zebra RPC {method} returned an invalid result.")
        return payload_out

    def get_testnet_info(self) -> Dict[str, Any]:
        response = self._rpc("getblockchaininfo", timeout=2.0)
        info = response["result"]
        chain = str(info.get("chain", "")).lower()
        try:
            height = int(info.get("blocks", -1))
        except (TypeError, ValueError):
            height = -1
        if chain not in {"test", "testnet"} and "testnet" not in chain:
            raise RuntimeError(f"Refusing broadcast: configured node is not Testnet (chain={chain!r}).")
        if height < IRONWOOD_TESTNET_ACTIVATION_HEIGHT:
            raise RuntimeError(
                f"Refusing Ironwood broadcast: node height {height} is below "
                f"Testnet NU6.3 activation {IRONWOOD_TESTNET_ACTIVATION_HEIGHT}."
            )
        return info

    def is_live_rpc_available(self) -> bool:
        try:
            self.get_testnet_info()
            return True
        except Exception as exc:
            logger.debug("Ironwood Testnet RPC unavailable/not eligible: %s", exc)
            return False

    @staticmethod
    def _validate_candidate(bundle: SettlementBundle) -> Optional[str]:
        if not getattr(bundle, "consensus_ready", False):
            return "Bundle is marked simulation-only / not consensus-ready."
        raw_hex = (getattr(bundle, "raw_tx_hex", "") or "").strip()
        if not raw_hex:
            return "No serialized raw transaction is present."
        if len(raw_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
            return "Raw transaction must be even-length hexadecimal."
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            return "Raw transaction is not valid hexadecimal."
        declared_size = int(getattr(bundle, "raw_tx_bytes_len", -1))
        if declared_size != len(raw):
            return f"Raw transaction size mismatch: declared {declared_size}, actual {len(raw)}."
        expected_txid = str(getattr(bundle, "tx_id", "") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_txid):
            return "A 32-byte expected transaction ID is required."
        # v6 header/version-group/branch IDs are checked before sending. The node performs
        # authoritative consensus verification of proofs, signatures, anchor and balance.
        if len(raw) < 12:
            return "Raw transaction is too short to contain a v6 header."
        if int.from_bytes(raw[0:4], "little") != 0x80000006:
            return "Raw transaction header is not version 6."
        if int.from_bytes(raw[4:8], "little") != 0xD884B698:
            return "Raw transaction version-group ID is not v6."
        if int.from_bytes(raw[8:12], "little") not in {0x37A5165B, 0x77190AD9}:
            return "Raw transaction does not use a supported v6 branch ID (NU6.3 or NU7)."
        return None

    def broadcast(self, bundle: SettlementBundle) -> Dict[str, Any]:
        """
        Submit only a consensus-ready Transaction v6 to a real NU6.3 Testnet node.
        No synthetic mining, no local consensus claims, and no fake confirmations.
        """
        reason = self._validate_candidate(bundle)
        if reason:
            return {
                "status": "REJECTED_NOT_CONSENSUS_READY",
                "broadcast": False,
                "confirmed": False,
                "tx_id": None,
                "simulation_id": getattr(bundle, "simulation_id", None),
                "confirmations": 0,
                "reason": reason,
            }

        try:
            info = self.get_testnet_info()
        except Exception as exc:
            return {
                "status": "TESTNET_RPC_UNAVAILABLE",
                "broadcast": False,
                "confirmed": False,
                "tx_id": None,
                "confirmations": 0,
                "reason": str(exc),
            }

        raw_tx_hex = bundle.raw_tx_hex.strip()
        try:
            response = self._rpc("sendrawtransaction", [raw_tx_hex], timeout=10.0)
            txid = response.get("result")
            if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", txid):
                raise RuntimeError("Zebra returned no valid transaction ID.")
        except Exception as exc:
            logger.warning("Zebra rejected/failed to accept Ironwood transaction: %s", exc)
            return {
                "status": "REJECTED_BY_TESTNET_NODE",
                "broadcast": False,
                "confirmed": False,
                "tx_id": None,
                "expected_tx_id": bundle.tx_id,
                "confirmations": 0,
                "reason": str(exc),
            }

        txid = txid.lower()
        expected_txid = bundle.tx_id.lower()
        txid_matches = txid == expected_txid
        record = {
            "txid": txid,
            "expected_txid": expected_txid,
            "txid_matches": txid_matches,
            "status": "BROADCAST_PENDING" if txid_matches else "BROADCAST_TXID_MISMATCH",
            "network": "Zcash Testnet (Ironwood / NU6.3)",
            "node_height_at_broadcast": info.get("blocks"),
            "version_group_id": "0xd884b698",
            "consensus_branch_id": "0x37a5165b",
            "raw_tx_len": bundle.raw_tx_bytes_len,
            "confirmations": 0,
            "confirmed": False,
            "broadcast": True,
            "explorer_url": f"https://testnet.zcashexplorer.app/tx/{txid}",
            "live_node": True,
            "note": "Accepted for broadcast; mined confirmation has not been checked.",
        }
        self.broadcast_history[txid] = record
        return record

    def get_transaction(self, txid: str) -> Optional[Dict[str, Any]]:
        """Returns this process's broadcast receipt, not a guarantee of on-chain confirmation."""
        return self.broadcast_history.get(txid)
