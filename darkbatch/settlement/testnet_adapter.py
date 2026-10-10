"""
DarkBatch settlement adapter.

Important safety properties:
- A local simulator is never described as a Zcash Testnet node or confirmation.
- Simulation fallback is opt-in (DARKBATCH_ALLOW_SIMULATION=true or allow_simulation=True).
- Live broadcasts are blocked unless the transaction builder explicitly certifies the raw
  transaction as safe for broadcast. The current legacy bundle builder does not certify it.
- Successful sendrawtransaction means "broadcast/mempool", not "confirmed".
"""
import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from darkbatch.settlement.v6_bundle import SettlementBundle
from darkbatch.node.simulator import ZcashNodeSimulator

logger = logging.getLogger("darkbatch.settlement.adapter")
TESTNET_NU63_ACTIVATION_HEIGHT = 4_134_000
# Deliberately hard-disabled until real-note selection, PCZT composition, spend authorization,
# and a matching multi-action proof are integrated and independently validated.
LIVE_SETTLEMENT_IMPLEMENTED = False
_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class TestnetSettlementAdapter:
    """Connects a settlement bundle to Zebra Testnet without upgrading simulations to success."""

    def __init__(
        self,
        node_simulator: Optional[ZcashNodeSimulator] = None,
        rpc_url: Optional[str] = None,
        rpc_user: Optional[str] = None,
        rpc_password: Optional[str] = None,
        allow_simulation: Optional[bool] = None,
    ):
        self.node_simulator = node_simulator or ZcashNodeSimulator()
        self.rpc_url = (
            rpc_url if rpc_url is not None
            else os.getenv("ZCASH_TESTNET_RPC_URL", "http://127.0.0.1:18232")
        )
        self.rpc_user = rpc_user if rpc_user is not None else os.getenv("ZCASH_TESTNET_RPC_USER", "")
        self.rpc_password = rpc_password if rpc_password is not None else os.getenv("ZCASH_TESTNET_RPC_PASS", "")
        if allow_simulation is None:
            allow_simulation = os.getenv("DARKBATCH_ALLOW_SIMULATION", "false").strip().lower() in {
                "1", "true", "yes", "on"
            }
        self.allow_simulation = bool(allow_simulation)
        self.broadcast_history: Dict[str, Dict[str, Any]] = {}

    def _rpc_call(self, method: str, params: Optional[list] = None, timeout: float = 3.0) -> Any:
        if not self.rpc_url:
            raise RuntimeError("ZCASH_TESTNET_RPC_URL is not configured")
        payload = {
            "jsonrpc": "1.0",
            "id": "darkbatch",
            "method": method,
            "params": params or [],
        }
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        if self.rpc_user and self.rpc_password:
            token = base64.b64encode(f"{self.rpc_user}:{self.rpc_password}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Zebra RPC HTTP {exc.code}: {detail}") from exc
        except Exception as exc:
            raise RuntimeError(f"Zebra RPC call {method} failed: {exc}") from exc
        if body.get("error") is not None:
            raise RuntimeError(f"Zebra RPC {method} error: {body['error']}")
        if "result" not in body:
            raise RuntimeError(f"Zebra RPC {method} returned no result")
        return body["result"]

    def get_live_chain_info(self) -> Optional[Dict[str, Any]]:
        """Return actual node information; return None when RPC cannot be reached."""
        try:
            result = self._rpc_call("getblockchaininfo", timeout=1.5)
            return result if isinstance(result, dict) else None
        except Exception:
            return None

    def is_live_rpc_available(self) -> bool:
        """True only when activated Testnet chain info and a Zebra network agent are confirmed."""
        info = self.get_live_chain_info()
        if not info:
            return False
        chain = str(info.get("chain", "")).lower()
        try:
            height = int(info.get("blocks", -1))
        except (TypeError, ValueError):
            return False
        # Zebra reports its user-agent through getnetworkinfo, not getblockchaininfo.
        try:
            network_info = self._rpc_call("getnetworkinfo", timeout=1.5)
        except Exception:
            return False
        if not isinstance(network_info, dict):
            return False
        subversion = str(network_info.get("subversion", "")).lower()
        return (
            chain in {"test", "testnet"}
            and height >= TESTNET_NU63_ACTIVATION_HEIGHT
            and "zebra" in subversion
        )

    def _simulate(self, bundle: SettlementBundle) -> Dict[str, Any]:
        """Run a local demo only, with no real-network success claims."""
        bundle_dict = {
            "tx_id": bundle.tx_id,
            "version": bundle.tx_version,
            "version_group_id": bundle.version_group_id,
            "consensus_branch_id": bundle.consensus_branch_id,
            "epoch_id": bundle.epoch_id,
            "clearing_price_usd": bundle.clearing_price_usd,
            "total_volume_zec": bundle.total_volume_zec,
            "action_groups": [
                {
                    "group_id": group.group_id,
                    "intent_id": group.intent_id,
                    "direction": group.direction,
                    "anchor_hex": group.anchor_hex,
                    "net_value_balance_zat": group.net_value_balance_zat,
                    "actions": [
                        {
                            "type": "SWAP",
                            "cv_point": group.swap_action.cv_net_hex,
                            "nullifier": group.swap_action.nullifier_hex,
                            "rk": group.swap_action.rk_hex,
                            "cm_point": group.swap_action.cm_star_hex,
                            "memo_hex": group.swap_action.encrypted_memo_hex,
                        },
                        {
                            "type": "FEE",
                            "cv_point": group.fee_action.cv_fee_hex,
                            "matcher_fee_zat": group.fee_action.matcher_fee_zat,
                            "miner_fee_zat": group.fee_action.miner_fee_zat,
                        },
                    ],
                }
                for group in bundle.action_groups
            ],
            "raw_tx_hex": bundle.raw_tx_hex,
            "raw_tx_bytes_len": bundle.raw_tx_bytes_len,
            "created_at": bundle.created_at,
        }
        ok, simulated_hash = self.node_simulator.submit_settlement_bundle(bundle_dict)
        if not ok:
            raise RuntimeError(f"Local simulation rejected the bundle: {simulated_hash}")
        record = {
            "txid": None,
            "simulation_id": bundle.tx_id,
            "status": "SIMULATED_ONLY",
            "network": "DarkBatch local simulator (not Zcash Testnet)",
            "version_group_id": hex(bundle.version_group_id),
            "consensus_branch_id": hex(bundle.consensus_branch_id),
            "simulation_block_height": self.node_simulator.height,
            "simulation_block_hash": simulated_hash,
            "simulation_anchor": self.node_simulator.current_anchor(),
            "actions_count": len(bundle.action_groups),
            "raw_tx_len": bundle.raw_tx_bytes_len,
            "confirmations": 0,
            "explorer_url": None,
            "live_node": False,
            "simulation_only": True,
            "note": "No transaction was broadcast to Zcash. This result is local simulation only.",
        }
        self.broadcast_history[bundle.tx_id] = record
        return record

    def broadcast(self, bundle: SettlementBundle) -> Dict[str, Any]:
        """
        Broadcast only a bundle explicitly certified by a future protocol-valid builder.
        Current SettlementBundleBuilder deliberately leaves live_broadcast_safe=False.
        """
        live_ready = self.is_live_rpc_available()
        if not live_ready:
            if self.allow_simulation:
                return self._simulate(bundle)
            raise RuntimeError(
                "Live Zcash Testnet RPC is unavailable or not at NU6.3 activation; "
                "refusing to treat local simulation as settlement. "
                "Set DARKBATCH_ALLOW_SIMULATION=true only for local demonstrations."
            )

        if not LIVE_SETTLEMENT_IMPLEMENTED or not getattr(bundle, "live_broadcast_safe", False):
            raise RuntimeError(
                "Refusing live broadcast: collaborative PCZT settlement is not implemented. "
                "The current assembler does not consume real unspent notes, participant-authorized "
                "spends, and a matching multi-action Halo 2 proof."
            )

        # The node's own consensus validator is the final gate; do not silently simulate on failure.
        live_txid = self._rpc_call("sendrawtransaction", [bundle.raw_tx_hex], timeout=10.0)
        if not isinstance(live_txid, str) or not _TXID_RE.fullmatch(live_txid):
            raise RuntimeError("Zebra returned an invalid transaction ID; broadcast status is unknown")

        record = {
            "txid": live_txid.lower(),
            "status": "BROADCAST_PENDING_CONFIRMATION",
            "network": "Zcash Testnet",
            "version_group_id": hex(bundle.version_group_id),
            "consensus_branch_id": hex(bundle.consensus_branch_id),
            "actions_count": len(bundle.action_groups),
            "raw_tx_len": bundle.raw_tx_bytes_len,
            "confirmations": 0,
            "block_hash": None,
            "explorer_url": f"https://testnet.zcashexplorer.app/tx/{live_txid.lower()}",
            "live_node": True,
            "simulation_only": False,
        }
        self.broadcast_history[live_txid.lower()] = record
        return record

    def broadcast_raw_transaction(
        self,
        raw_tx_hex: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a locally extracted V6 transaction to a real activated Zebra Testnet node.

        Separate from the FBA bundle adapter: this does not associate an epoch, update balances,
        or claim a cross-asset swap has settled. The node must accept the complete transaction.
        """
        if not self.is_live_rpc_available():
            raise RuntimeError(
                "Activated Zebra Testnet RPC is unavailable; refusing to broadcast a raw transaction."
            )

        normalized = "".join(raw_tx_hex.split()).lower()
        if not normalized or len(normalized) % 2 or not re.fullmatch(r"[0-9a-f]+", normalized):
            raise ValueError("raw transaction must be a non-empty even-length hexadecimal string")
        raw = bytes.fromhex(normalized)
        if len(raw) < 1000:
            raise ValueError(
                f"raw transaction is too short to be a complete shielded V6 transaction: {len(raw)} bytes"
            )
        if int.from_bytes(raw[:4], "little") != 0x80000006:
            raise ValueError("raw transaction header is not Zcash Transaction V6 (0x80000006)")
        branch_id = int.from_bytes(raw[4:8], "little")
        if branch_id != 0x37A5165B:
            raise ValueError(
                f"raw transaction consensus branch ID is 0x{branch_id:08x}; "
                "expected NU6.3 Testnet branch 0x37a5165b"
            )

        txid = self._rpc_call("sendrawtransaction", [normalized], timeout=15.0)
        if not isinstance(txid, str) or not _TXID_RE.fullmatch(txid):
            raise RuntimeError("Zebra did not return a valid 32-byte transaction ID; broadcast status is unknown")

        record = {
            "txid": txid.lower(),
            "status": "BROADCAST_PENDING_CONFIRMATION",
            "network": "Zcash Testnet",
            "source": "local official-PCZT extraction",
            "transaction_version": 6,
            "raw_tx_len": len(raw),
            "confirmations": 0,
            "block_hash": None,
            "block_height": None,
            "explorer_url": f"https://testnet.zcashexplorer.app/tx/{txid.lower()}",
            "live_node": True,
            "simulation_only": False,
            "epoch_settled": False,
            "quote_leg_status": "NOT_SETTLED",
            "note": "Broadcast accepted by RPC only; wait for and verify block confirmation. This is not FBA/USDC settlement.",
        }
        if metadata:
            # Metadata is limited to non-secret settlement accounting data. Never attach PCZT,
            # note openings, viewing keys, or spending keys to transaction history.
            record.update({
                key: value for key, value in metadata.items()
                if key in {
                    "epoch_id", "clearing_price_usd", "total_cleared_zec",
                    "total_cleared_usd", "intent_ids", "proof_report_txid",
                    "build_report_input_total_zat", "build_report_recipient_total_zat",
                    "build_report_fee_zat", "build_report_change_zat",
                    "build_report_input_count", "build_report_recipient_output_count",
                }
            })
        self.broadcast_history[txid.lower()] = record
        return record

    def get_transaction(self, txid: str) -> Optional[Dict[str, Any]]:
        """Return cached state, refreshing live transaction confirmations when possible."""
        record = self.broadcast_history.get(txid)
        if not record:
            return None
        if not record.get("live_node"):
            return record
        try:
            result = self._rpc_call("getrawtransaction", [txid, 1], timeout=3.0)
            if isinstance(result, dict):
                confirmations = max(0, int(result.get("confirmations", 0) or 0))
                record["confirmations"] = confirmations
                record["block_hash"] = result.get("blockhash")
                record["status"] = "MEMPOOL" if confirmations == 0 else "CONFIRMED"
                record["simulation_only"] = False
                if confirmations >= 1:
                    if not record.get("block_hash"):
                        record["status"] = "CONFIRMATION_DETAILS_INCOMPLETE"
                    else:
                        header = self._rpc_call("getblockheader", [record["block_hash"]], timeout=3.0)
                        if isinstance(header, dict) and header.get("height") is not None:
                            record["block_height"] = int(header["height"])
                        else:
                            record["status"] = "CONFIRMATION_DETAILS_INCOMPLETE"
        except Exception as exc:
            # Keep last known state; a failed lookup is not evidence of confirmation.
            record["status_check_error"] = str(exc)
        return record
