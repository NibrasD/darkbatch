"""
DarkBatch Autonomous Solver Daemon
Executes continuous Frequent Batch Auction (FBA) clearing, settles on Ironwood node simulator,
and distributes encrypted receipts to market participants.
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
        wallets_map: Optional[Dict[str, ShieldedWallet]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end clearing of an epoch:
        1. Solves FBA uniform clearing price.
        2. Builds ZIP 228 / v6 Settlement Bundle.
        3. Submits bundle to the Zcash Node (mining a block and verifying nullifiers).
        4. Updates wallet balances and gives execution receipts to traders.
        """
        start = time.perf_counter()
        self.bundle_builder.ironwood_anchor = self.node.current_anchor()

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

        # 2. Build Bundle
        intents_map = {i.intent_id: i for i in intents}
        bundle = self.bundle_builder.build_bundle(clear_result, intents_map)

        # 3. Submit to Simulated Node
        bundle_dict = {
            "tx_id": bundle.tx_id,
            "version": bundle.tx_version,
            "epoch_id": bundle.epoch_id,
            "clearing_price_usd": bundle.clearing_price_usd,
            "total_volume_zec": bundle.total_volume_zec,
            "aggregated_binding_pubkey": bundle.aggregated_binding_pubkey_hex,
            "action_groups": [
                {
                    "group_id": ag.action_group_id,
                    "intent_id": ag.intent_id,
                    "direction": ag.direction,
                    "anchor": ag.anchor_root_hex,
                    "actions": [
                        {
                            "action_index": a.action_index,
                            "nullifier": a.nullifier_hex,
                            "cm_point": a.cm_point_hex,
                            "cv_point": a.cv_point_hex,
                            "encrypted_memo": a.encrypted_memo_hex
                        } for a in ag.actions
                    ]
                } for ag in bundle.action_groups
            ]
        }
        
        success, block_hash = self.node.submit_settlement_bundle(bundle_dict)
        if not success:
            raise RuntimeError(f"Node rejected settlement bundle: {block_hash}")

        # 4. Update Wallets & Balances if provided
        if wallets_map:
            # Buyers receive ZEC and spend USD
            for fill in clear_result.buy_fills:
                wallet = wallets_map.get(fill.shielded_address)
                if wallet:
                    wallet.shielded_balance_zat += fill.filled_zat
                    wallet.quote_balance_cents -= int(round(fill.quote_filled_usd * 100))
            # Sellers spend ZEC and receive USD
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
            "execution_latency_ms": round(elapsed_ms, 2)
        }
        self.solved_history.append(summary)
        return summary
