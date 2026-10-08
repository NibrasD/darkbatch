"""
DarkBatch Autonomous Solver Daemon
Executes continuous Frequent Batch Auction (FBA) clearing, settles on Ironwood node simulator,
and distributes strictly 512-byte encrypted receipts directly to each participant's viewing key.
"""

from dataclasses import dataclass, field
import time
from typing import Dict, List, Optional, Any
from darkbatch.core.intent import SwapOrderIntent, OrderDirection
from darkbatch.engine.batch_solver import BatchAuctionSolver, BatchClearResult
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder, SettlementBundle
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.core.wallet import ShieldedWallet

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
    def __init__(self, node: ZcashNodeSimulator, solver_fee_bps: int = 10):
        self.node = node
        self.solver_fee_bps = solver_fee_bps
        self.matching_engine = BatchAuctionSolver(solver_fee_bps=solver_fee_bps)
        self.bundle_builder = SettlementBundleBuilder(ironwood_anchor=node.current_anchor())
        self.stats = SolverStats()
        self.solved_history: List[Dict[str, Any]] = []

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

        # 2. Build ZIP 228 Bundle
        intents_map = {i.intent_id: i for i in intents}
        bundle = self.bundle_builder.build_bundle(clear_result, intents_map, wallets_ivk_map=wallets_ivk_map)

        # 3. Format bundle for Node consensus verification
        bundle_dict = {
            "tx_id": bundle.tx_id,
            "version": bundle.tx_version,
            "version_group_id": bundle.version_group_id,
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
            raise RuntimeError(f"Node rejected settlement bundle: {block_hash}")

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
            "status": "SETTLED_AND_MINED",
            "clearing_price_usd": clear_result.clearing_price_usd,
            "cleared_zec": clear_result.total_cleared_zec,
            "cleared_usd": clear_result.total_cleared_usd,
            "tx_id": bundle.tx_id,
            "block_hash": block_hash,
            "block_height": self.node.height,
            "buy_fills_count": len(clear_result.buy_fills),
            "sell_fills_count": len(clear_result.sell_fills),
            "solver_fee_zec": clear_result.solver_fee_zec,
            "execution_latency_ms": round(elapsed_ms, 2),
            "raw_tx_bytes_len": bundle.raw_tx_bytes_len
        }
        self.solved_history.append(summary)
        return summary
