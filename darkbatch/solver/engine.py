"""
DarkBatch FBA matching engine.

Without a settlement adapter, this class supports legacy deterministic local tests only.
The API injects a strict adapter that refuses live broadcast until cooperative PCZT settlement
is actually implemented and verified. Local simulation results are not Zcash transactions.
"""

from dataclasses import dataclass, field
import time
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, List, Optional, Any
from darkbatch.core.intent import SwapOrderIntent, OrderDirection
from darkbatch.engine.batch_solver import BatchAuctionSolver, BatchClearResult
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder, SettlementBundle
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.core.wallet import ShieldedWallet

def _quote_micro_total(total_zat: int, price_usd: float) -> int:
    """USDC has 6 decimals; convert an exact ZEC fill and uniform price to micro-USDC."""
    amount = (Decimal(int(total_zat)) * Decimal(str(price_usd)) / Decimal(100))
    return int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _allocate_quote_micro(fills: List[Any], price_usd: float) -> Dict[str, int]:
    """Largest-remainder allocation so both sides sum to one identical USDC micro-unit total."""
    total_zat = sum(int(fill.filled_zat) for fill in fills)
    if total_zat <= 0 or not fills:
        return {}
    total_micro = _quote_micro_total(total_zat, price_usd)
    parts = []
    assigned = 0
    for index, fill in enumerate(fills):
        base, remainder = divmod(total_micro * int(fill.filled_zat), total_zat)
        parts.append({"index": index, "intent_id": fill.intent_id, "base": base, "remainder": remainder})
        assigned += base
    left = total_micro - assigned
    parts.sort(key=lambda part: (-part["remainder"], part["intent_id"], part["index"]))
    for part in parts[:left]:
        part["base"] += 1
    return {part["intent_id"]: part["base"] for part in parts}


@dataclass
class SolverStats:
    total_epochs_solved: int = 0
    total_volume_cleared_zec: float = 0.0
    total_volume_cleared_usd: float = 0.0
    total_solver_revenue_zec: float = 0.0
    total_settlement_txs_mined: int = 0
    avg_latency_ms: float = 0.0

class AutonomousSolverDaemon:
    """
    Autonomous Solver responsible for batch matching and on-chain bundle submission.
    """
    def __init__(
        self,
        node: ZcashNodeSimulator,
        solver_fee_bps: int = 10,
        settlement_adapter: Optional[Any] = None,
    ):
        self.node = node
        self.settlement_adapter = settlement_adapter
        self.solver_fee_bps = solver_fee_bps
        self.matching_engine = BatchAuctionSolver(solver_fee_bps=solver_fee_bps)
        self.bundle_builder = SettlementBundleBuilder(ironwood_anchor=node.current_anchor())
        self.stats = SolverStats()
        self.solved_history: List[Dict[str, Any]] = []
        # Sensitive FBA fills are kept in-process and returned only to the local PCZT agent.
        self.local_settlement_plans: Dict[int, Dict[str, Any]] = {}

    def run_epoch_settlement(
        self,
        epoch_id: int,
        intents: List[SwapOrderIntent],
        wallets_map: Optional[Dict[str, ShieldedWallet]] = None,
        wallets_ivk_map: Optional[Dict[str, bytes]] = None
    ) -> Dict[str, Any]:
        start = time.perf_counter()
        self.bundle_builder.ironwood_anchor = self.node.current_anchor()

        # If wallets_map is provided and wallets_ivk_map is not, derive it
        if wallets_map and not wallets_ivk_map:
            wallets_ivk_map = {addr: w.ivk for addr, w in wallets_map.items()}

        # 1. Solve Batch
        clear_result = self.matching_engine.solve(epoch_id, intents)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if clear_result.total_cleared_zec == 0:
            return {
                "epoch_id": epoch_id,
                "status": "NO_CROSSING_LIQUIDITY",
                "cleared_zec": 0.0,
                "clearing_price_usd": 0.0,
                "tx_id": None,
                "block_hash": None
            }

        # The public API never sends mock IVKs or the legacy transaction-shaped bundle to Zebra.
        # It publishes only a summary and keeps the participant-level fill plan behind a local token.
        if self.settlement_adapter is not None:
            intent_by_id = {intent.intent_id: intent for intent in intents}
            buy_quote_micro = _allocate_quote_micro(clear_result.buy_fills, clear_result.clearing_price_usd)
            sell_quote_micro = _allocate_quote_micro(clear_result.sell_fills, clear_result.clearing_price_usd)
            plan = {
                "schema": "darkbatch.fba-local-pczt-plan.v1",
                "epoch_id": epoch_id,
                "clearing_price_usd": clear_result.clearing_price_usd,
                "total_cleared_zec": clear_result.total_cleared_zec,
                "total_cleared_usd": clear_result.total_cleared_usd,
                "quote_asset": "USDC",
                "quote_decimals": 6,
                "quote_total_micro": _quote_micro_total(
                    sum(int(fill.filled_zat) for fill in clear_result.buy_fills),
                    clear_result.clearing_price_usd,
                ),
                "solver_fee_zec": clear_result.solver_fee_zec,
                "buy_fills": [
                    {
                        "intent_id": f.intent_id,
                        "direction": f.direction.value,
                        "original_zat": f.original_zat,
                        "filled_zat": f.filled_zat,
                        "clearing_price_usd": f.clearing_price_usd,
                        "quote_filled_usd": f.quote_filled_usd,
                        "shielded_address": f.shielded_address,
                        "fill_percentage": f.fill_percentage,
                        "is_marginal": f.is_marginal,
                        "quote_address": intent_by_id[f.intent_id].quote_address,
                        "quote_amount_micro": buy_quote_micro.get(f.intent_id, 0),
                    }
                    for f in clear_result.buy_fills
                ],
                "sell_fills": [
                    {
                        "intent_id": f.intent_id,
                        "direction": f.direction.value,
                        "original_zat": f.original_zat,
                        "filled_zat": f.filled_zat,
                        "clearing_price_usd": f.clearing_price_usd,
                        "quote_filled_usd": f.quote_filled_usd,
                        "shielded_address": f.shielded_address,
                        "fill_percentage": f.fill_percentage,
                        "is_marginal": f.is_marginal,
                        "quote_address": intent_by_id[f.intent_id].quote_address,
                        "quote_amount_micro": sell_quote_micro.get(f.intent_id, 0),
                    }
                    for f in clear_result.sell_fills
                ],
                "intent_ids": sorted({f.intent_id for f in clear_result.buy_fills + clear_result.sell_fills}),
                "status": "LOCAL_PCZT_REQUIRED",
                "created_at": time.time(),
            }
            self.local_settlement_plans[epoch_id] = plan
            return {
                "epoch_id": epoch_id,
                "status": "LOCAL_PCZT_REQUIRED",
                "clearing_price_usd": clear_result.clearing_price_usd,
                "cleared_zec": clear_result.total_cleared_zec,
                "cleared_usd": clear_result.total_cleared_usd,
                "buy_fills_count": len(clear_result.buy_fills),
                "sell_fills_count": len(clear_result.sell_fills),
                "tx_id": None,
                "block_hash": None,
                "local_pczt_required": True,
                "quote_leg_status": "NOT_SETTLED",
                "message": "FBA matched locally. Build, sign, prove, and extract a real V6 PCZT with the local agent; no funds moved.",
            }

        # Legacy deterministic simulator path is retained for isolated unit tests only.
        # It is unreachable from the public API because the API injects a settlement adapter.
        # 2. Build ZIP 228 Bundle
        intents_map = {i.intent_id: i for i in intents}
        bundle = self.bundle_builder.build_bundle(clear_result, intents_map, wallets_ivk_map=wallets_ivk_map)

        # 3. Production/API path must use the strict settlement adapter.
        # Legacy direct simulator remains available only to deterministic local tests.
        if self.settlement_adapter is not None:
            try:
                receipt = self.settlement_adapter.broadcast(bundle)
            except Exception as exc:
                return {
                    "epoch_id": epoch_id,
                    "status": "SETTLEMENT_BLOCKED",
                    "reason": str(exc),
                    "proposed_clearing_price_usd": clear_result.clearing_price_usd,
                    "proposed_volume_zec": clear_result.total_cleared_zec,
                    "proposed_volume_usd": clear_result.total_cleared_usd,
                    "tx_id": None,
                    "block_hash": None,
                    "simulation_only": False,
                }

            receipt_status = receipt.get("status")
            if receipt_status != "CONFIRMED":
                # Broadcast/mempool is not settlement. Do not change participant balances,
                # mark intents filled, or increment "mined" metrics until confirmation.
                return {
                    "epoch_id": epoch_id,
                    "status": receipt_status or "BROADCAST_PENDING_CONFIRMATION",
                    "settlement": receipt,
                    "proposed_clearing_price_usd": clear_result.clearing_price_usd,
                    "proposed_volume_zec": clear_result.total_cleared_zec,
                    "proposed_volume_usd": clear_result.total_cleared_usd,
                    "tx_id": receipt.get("txid"),
                    "block_hash": receipt.get("block_hash"),
                    "simulation_only": bool(receipt.get("simulation_only", False)),
                }

            block_hash = receipt.get("block_hash")
            confirmed_height = receipt.get("block_height")
            confirmed_tx_id = receipt.get("txid") or bundle.tx_id
            if not block_hash or not confirmed_height or int(receipt.get("confirmations", 0)) < 1:
                raise RuntimeError("Adapter reported CONFIRMED without a block hash, height, and confirmation")

        else:
            # Explicit local test/demo compatibility path. This is not a live Zcash transaction.
            bundle_dict = {
                "tx_id": bundle.tx_id,
                "version": bundle.tx_version,
                "version_group_id": bundle.version_group_id,
                "consensus_branch_id": bundle.consensus_branch_id,
                "epoch_id": bundle.epoch_id,
                "clearing_price_usd": bundle.clearing_price_usd,
                "total_volume_zec": bundle.total_volume_zec,
                "aggregated_binding_pubkey": bundle.aggregated_binding_pubkey_hex,
                "raw_tx_hex": bundle.raw_tx_hex,
                "action_groups": [
                    {
                        "group_id": ag.group_id,
                        "intent_id": ag.intent_id,
                        "direction": ag.direction,
                        "anchor": ag.anchor_hex,
                        "actions": [
                            {
                                "type": "SWAP",
                                "cv_net": ag.swap_action.cv_net_hex,
                                "nullifier": ag.swap_action.nullifier_hex,
                                "rk": ag.swap_action.rk_hex,
                                "cm_point": ag.swap_action.cm_star_hex,
                                "encrypted_memo": ag.swap_action.encrypted_memo_hex
                            },
                            {
                                "type": "FEE",
                                "cv_fee": ag.fee_action.cv_fee_hex,
                                "matcher_fee_zat": ag.fee_action.matcher_fee_zat,
                                "miner_fee_zat": ag.fee_action.miner_fee_zat
                            }
                        ]
                    } for ag in bundle.action_groups
                ]
            }
            success, block_hash = self.node.submit_settlement_bundle(bundle_dict)
            if not success:
                raise RuntimeError(f"Local simulation rejected settlement bundle: {block_hash}")
            confirmed_tx_id = bundle.tx_id

        # 4. Update Wallets & Balances
        if wallets_map:
            for fill in clear_result.buy_fills:
                wallet = wallets_map.get(fill.shielded_address)
                if wallet:
                    wallet.shielded_balance_zat += fill.filled_zat
                    wallet.quote_balance_cents -= int(round(fill.quote_filled_usd * 100))
            for fill in clear_result.sell_fills:
                wallet = wallets_map.get(fill.shielded_address)
                if wallet:
                    wallet.shielded_balance_zat -= fill.filled_zat
                    wallet.quote_balance_cents += int(round(fill.quote_filled_usd * 100))

        # 5. Update Telemetry
        self.stats.total_epochs_solved += 1
        self.stats.total_volume_cleared_zec += clear_result.total_cleared_zec
        self.stats.total_volume_cleared_usd += clear_result.total_cleared_usd
        self.stats.total_solver_revenue_zec += clear_result.solver_fee_zec
        self.stats.total_settlement_txs_mined += 1
        self.stats.avg_latency_ms = (self.stats.avg_latency_ms + elapsed_ms) / 2.0

        summary = {
            "epoch_id": epoch_id,
            "status": "SETTLED_AND_MINED" if self.settlement_adapter is None else "CONFIRMED",
            "clearing_price_usd": clear_result.clearing_price_usd,
            "cleared_zec": clear_result.total_cleared_zec,
            "cleared_usd": clear_result.total_cleared_usd,
            "tx_id": confirmed_tx_id,
            "block_hash": block_hash,
            "block_height": self.node.height if self.settlement_adapter is None else int(confirmed_height),
            "buy_fills_count": len(clear_result.buy_fills),
            "sell_fills_count": len(clear_result.sell_fills),
            "solver_fee_zec": clear_result.solver_fee_zec,
            "execution_latency_ms": round(elapsed_ms, 2),
            "raw_tx_bytes_len": bundle.raw_tx_bytes_len
        }
        self.solved_history.append(summary)
        return summary
