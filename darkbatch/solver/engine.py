"""
DarkBatch Autonomous Solver Daemon
Executes off-chain Frequent Batch Auction (FBA) matching and emits simulation-only settlement records.
This daemon does not spend Ironwood notes or claim on-chain settlement.
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

        # Consensus safety boundary: this application currently has only simulated
        # wallets/intents and no authorized Ironwood spends or Merkle witnesses.
        # Never submit this record to the local block simulator and never claim mined.
        self.stats.avg_latency_ms = (self.stats.avg_latency_ms + elapsed_ms) / 2.0
        summary = {
            "epoch_id": epoch_id,
            "status": "SIMULATED_ONLY",
            "settlement_mode": "LOCAL_FBA_SIMULATION",
            "consensus_ready": False,
            "simulation_id": bundle.simulation_id,
            "tx_id": None,
            "block_hash": None,
            "block_height": None,
            "clearing_price_usd": clear_result.clearing_price_usd,
            "cleared_zec": clear_result.total_cleared_zec,
            "cleared_usd": clear_result.total_cleared_usd,
            "buy_fills_count": len(clear_result.buy_fills),
            "sell_fills_count": len(clear_result.sell_fills),
            "solver_fee_zec": clear_result.solver_fee_zec,
            "execution_latency_ms": round(elapsed_ms, 2),
            "raw_tx_hex": "",
            "raw_tx_bytes_len": 0,
            "validation_blockers": bundle.validation_blockers,
        }
        self.solved_history.append(summary)
        return summary
