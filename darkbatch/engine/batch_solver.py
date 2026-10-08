"""
DarkBatch Frequent Batch Auction (FBA) Solver Engine
Implements the uniform clearing price discovery algorithm inspired by Archer Exchange:
- MEV-neutral: Orders within an epoch are treated as a simultaneous discrete batch.
- Fair uniform price: Maximizes aggregate cleared volume at single market equilibrium P*.
- Proportional rationing: Fair pro-rata fill for marginal limit orders at the clearing boundary.
"""

from dataclasses import dataclass, field
import time
from typing import List, Dict, Optional, Tuple
from darkbatch.core.intent import SwapOrderIntent, OrderDirection

@dataclass
class MatchedFill:
    intent_id: str
    direction: OrderDirection
    original_zat: int
    filled_zat: int
    clearing_price_usd: float
    quote_filled_usd: float
    shielded_address: str
    fill_percentage: float

@dataclass
class BatchClearResult:
    epoch_id: int
    clearing_price_usd: float
    total_cleared_zec: float
    total_cleared_usd: float
    buy_fills: List[MatchedFill] = field(default_factory=list)
    sell_fills: List[MatchedFill] = field(default_factory=list)
    unfilled_intents: List[str] = field(default_factory=list)
    solver_fee_zec: float = 0.0
    solver_execution_time_ms: float = 0.0

class BatchAuctionSolver:
    """
    Core Batch Auction Solver executing periodic discrete clearing cycles.
    """
    def __init__(self, solver_fee_bps: int = 10):
        # 10 bps = 0.1% protocol fee for solver coordination
        self.solver_fee_bps = solver_fee_bps

    def solve(self, epoch_id: int, intents: List[SwapOrderIntent]) -> BatchClearResult:
        """
        Calculates the Uniform Clearing Price P* that maximizes executed volume.
        """
        start_time = time.perf_counter()
        
        # Filter valid and non-expired intents
        valid_intents = [i for i in intents if i.verify_signature()]
        buys = [i for i in valid_intents if i.direction == OrderDirection.BUY_ZEC]
        sells = [i for i in valid_intents if i.direction == OrderDirection.SELL_ZEC]
        
        if not buys or not sells:
            # Cannot clear without two-sided liquidity
            return BatchClearResult(
                epoch_id=epoch_id,
                clearing_price_usd=0.0,
                total_cleared_zec=0.0,
                total_cleared_usd=0.0,
                unfilled_intents=[i.intent_id for i in valid_intents],
                solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
            )

        # Sort buyers descending by willingness to pay (highest limit price first)
        buys_sorted = sorted(buys, key=lambda x: x.limit_price_cents, reverse=True)
        # Sort sellers ascending by willingness to accept (lowest limit price first)
        sells_sorted = sorted(sells, key=lambda x: x.limit_price_cents)

        # Check if any overlap exists (highest bid >= lowest ask)
        if buys_sorted[0].limit_price_cents < sells_sorted[0].limit_price_cents:
            # No crossing orders
            return BatchClearResult(
                epoch_id=epoch_id,
                clearing_price_usd=0.0,
                total_cleared_zec=0.0,
                total_cleared_usd=0.0,
                unfilled_intents=[i.intent_id for i in valid_intents],
                solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
            )

        # Collect candidate clearing price thresholds
        price_candidates = set()
        for b in buys_sorted:
            price_candidates.add(b.limit_price_cents)
        for s in sells_sorted:
            price_candidates.add(s.limit_price_cents)

        best_clearing_price_cents = 0
        max_cleared_zat = 0

        # Evaluate candidate clearing prices
        for p in sorted(price_candidates):
            # Demand at price p: sum of all buys with limit_price >= p
            demand_zat = sum(b.base_amount_zat for b in buys_sorted if b.limit_price_cents >= p)
            # Supply at price p: sum of all sells with limit_price <= p
            supply_zat = sum(s.base_amount_zat for s in sells_sorted if s.limit_price_cents <= p)
            
            matched_zat = min(demand_zat, supply_zat)
            if matched_zat > max_cleared_zat:
                max_cleared_zat = matched_zat
                best_clearing_price_cents = p
            elif matched_zat == max_cleared_zat and max_cleared_zat > 0:
                # If tied, pick the midpoint of the price range to balance buyer/seller surplus
                best_clearing_price_cents = (best_clearing_price_cents + p) // 2

        if max_cleared_zat == 0:
            return BatchClearResult(
                epoch_id=epoch_id,
                clearing_price_usd=0.0,
                total_cleared_zec=0.0,
                total_cleared_usd=0.0,
                unfilled_intents=[i.intent_id for i in valid_intents],
                solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
            )

        clearing_price_usd = best_clearing_price_cents / 100.0

        # Allocate fills to buyers
        eligible_buys = [b for b in buys_sorted if b.limit_price_cents >= best_clearing_price_cents]
        eligible_sells = [s for s in sells_sorted if s.limit_price_cents <= best_clearing_price_cents]

        total_buy_demand_zat = sum(b.base_amount_zat for b in eligible_buys)
        total_sell_supply_zat = sum(s.base_amount_zat for s in eligible_sells)

        buy_fills: List[MatchedFill] = []
        sell_fills: List[MatchedFill] = []
        unfilled: List[str] = []

        # If buy demand exceeds supply, pro-rata ration the buyers
        buy_ratio = min(1.0, max_cleared_zat / total_buy_demand_zat) if total_buy_demand_zat > 0 else 0.0
        # If sell supply exceeds demand, pro-rata ration the sellers
        sell_ratio = min(1.0, max_cleared_zat / total_sell_supply_zat) if total_sell_supply_zat > 0 else 0.0

        for b in eligible_buys:
            filled_zat = int(round(b.base_amount_zat * buy_ratio))
            if filled_zat > 0:
                quote_val = (filled_zat / 100_000_000.0) * clearing_price_usd
                buy_fills.append(MatchedFill(
                    intent_id=b.intent_id,
                    direction=b.direction,
                    original_zat=b.base_amount_zat,
                    filled_zat=filled_zat,
                    clearing_price_usd=clearing_price_usd,
                    quote_filled_usd=quote_val,
                    shielded_address=b.shielded_address,
                    fill_percentage=buy_ratio * 100.0
                ))
            else:
                unfilled.append(b.intent_id)

        for s in eligible_sells:
            filled_zat = int(round(s.base_amount_zat * sell_ratio))
            if filled_zat > 0:
                quote_val = (filled_zat / 100_000_000.0) * clearing_price_usd
                sell_fills.append(MatchedFill(
                    intent_id=s.intent_id,
                    direction=s.direction,
                    original_zat=s.base_amount_zat,
                    filled_zat=filled_zat,
                    clearing_price_usd=clearing_price_usd,
                    quote_filled_usd=quote_val,
                    shielded_address=s.shielded_address,
                    fill_percentage=sell_ratio * 100.0
                ))
            else:
                unfilled.append(s.intent_id)

        # Add ineligible intents to unfilled list
        for b in buys_sorted:
            if b.limit_price_cents < best_clearing_price_cents:
                unfilled.append(b.intent_id)
        for s in sells_sorted:
            if s.limit_price_cents > best_clearing_price_cents:
                unfilled.append(s.intent_id)

        total_cleared_zec = max_cleared_zat / 100_000_000.0
        total_cleared_usd = total_cleared_zec * clearing_price_usd
        solver_fee_zec = total_cleared_zec * (self.solver_fee_bps / 10_000.0)

        return BatchClearResult(
            epoch_id=epoch_id,
            clearing_price_usd=clearing_price_usd,
            total_cleared_zec=total_cleared_zec,
            total_cleared_usd=total_cleared_usd,
            buy_fills=buy_fills,
            sell_fills=sell_fills,
            unfilled_intents=unfilled,
            solver_fee_zec=solver_fee_zec,
            solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
        )
