"""
DarkBatch experimental local Frequent Batch Auction (FBA) matching engine.
It implements a uniform-price clearing prototype with deterministic largest-remainder
allocation for integer zatoshis. This is not an audited market mechanism and does not by
itself establish MEV immunity or settle funds on Zcash.
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
    is_marginal: bool

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

def allocate_exact_pro_rata(target_zat: int, orders: List[SwapOrderIntent]) -> Dict[str, int]:
    """Allocate an integer target exactly by largest remainder, deterministic on intent_id."""
    if target_zat < 0:
        raise ValueError("pro-rata target cannot be negative")
    total_capacity = sum(order.base_amount_zat for order in orders)
    if target_zat > total_capacity:
        raise ValueError(f"pro-rata target {target_zat} exceeds marginal capacity {total_capacity}")
    if not orders:
        if target_zat:
            raise ValueError("cannot allocate positive target without marginal orders")
        return {}
    if total_capacity == 0:
        return {order.intent_id: 0 for order in orders}

    allocations: Dict[str, int] = {}
    remainders = []
    assigned = 0
    for order in orders:
        numerator = order.base_amount_zat * target_zat
        base, remainder = divmod(numerator, total_capacity)
        allocations[order.intent_id] = base
        assigned += base
        remainders.append((order.intent_id, remainder))
    leftover = target_zat - assigned
    remainders.sort(key=lambda item: (-item[1], item[0]))
    for intent_id, _remainder in remainders[:leftover]:
        allocations[intent_id] += 1
    if sum(allocations.values()) != target_zat:
        raise AssertionError("integer pro-rata allocation did not conserve the target")
    return allocations


class BatchAuctionSolver:
    """
    Frequent Batch Auction Solver with strict Inframarginal priority and Marginal pro-rata rationing.
    """
    def __init__(self, solver_fee_bps: int = 10):
        self.solver_fee_bps = solver_fee_bps

    def solve(self, epoch_id: int, intents: List[SwapOrderIntent]) -> BatchClearResult:
        start_time = time.perf_counter()

        # Ignore exact replay of an already-seen intent ID within one epoch.
        # The pro-rata allocator is keyed by intent_id, so duplicates must not be counted twice.
        valid_by_id: Dict[str, SwapOrderIntent] = {}
        for intent in intents:
            if intent.verify_signature():
                valid_by_id.setdefault(intent.intent_id, intent)
        valid_intents = list(valid_by_id.values())
        buys = [i for i in valid_intents if i.direction == OrderDirection.BUY_ZEC]
        sells = [i for i in valid_intents if i.direction == OrderDirection.SELL_ZEC]

        if not buys or not sells:
            return BatchClearResult(
                epoch_id=epoch_id,
                clearing_price_usd=0.0,
                total_cleared_zec=0.0,
                total_cleared_usd=0.0,
                unfilled_intents=[i.intent_id for i in valid_intents],
                solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
            )

        buys_sorted = sorted(buys, key=lambda x: x.limit_price_cents, reverse=True)
        sells_sorted = sorted(sells, key=lambda x: x.limit_price_cents)

        # If highest bid < lowest ask, no clearing possible
        if buys_sorted[0].limit_price_cents < sells_sorted[0].limit_price_cents:
            return BatchClearResult(
                epoch_id=epoch_id,
                clearing_price_usd=0.0,
                total_cleared_zec=0.0,
                total_cleared_usd=0.0,
                unfilled_intents=[i.intent_id for i in valid_intents],
                solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0
            )

        # Collect candidate clearing prices
        candidate_prices = set()
        for b in buys_sorted:
            candidate_prices.add(b.limit_price_cents)
        for s in sells_sorted:
            candidate_prices.add(s.limit_price_cents)

        max_cleared_zat = 0
        max_volume_candidates: List[Tuple[int, int, int]] = []

        # Find all prices maximizing min(Demand(P), Supply(P)).
        # Never average candidate prices: a synthetic midpoint can put too many orders
        # strictly inside the price and make "inframarginal 100%" exceed the matched volume.
        for p in sorted(candidate_prices):
            demand_zat = sum(b.base_amount_zat for b in buys_sorted if b.limit_price_cents >= p)
            supply_zat = sum(s.base_amount_zat for s in sells_sorted if s.limit_price_cents <= p)
            matched_zat = min(demand_zat, supply_zat)

            if matched_zat > max_cleared_zat:
                max_cleared_zat = matched_zat
                max_volume_candidates = [(p, demand_zat, supply_zat)]
            elif matched_zat == max_cleared_zat and max_cleared_zat > 0:
                max_volume_candidates.append((p, demand_zat, supply_zat))

        # Choose an observed price that puts the over-subscribed side at its marginal
        # limit: if demand is limiting, the lowest max-volume price rations sellers;
        # if supply is limiting, the highest max-volume price rations buyers.
        demand_limited = [entry for entry in max_volume_candidates if entry[1] <= entry[2]]
        if demand_limited:
            best_clearing_price_cents = min(entry[0] for entry in demand_limited)
        elif max_volume_candidates:
            best_clearing_price_cents = max(entry[0] for entry in max_volume_candidates)
        else:
            best_clearing_price_cents = 0

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

        # === PROPER FBA RATIONING ===
        # 1. Buyers:
        # - Inframarginal: limit_price > P* -> 100% filled
        # - Marginal: limit_price == P* -> prorated on remaining volume
        # - Out-of-money: limit_price < P* -> 0% filled
        infra_buys = [b for b in buys_sorted if b.limit_price_cents > best_clearing_price_cents]
        marginal_buys = [b for b in buys_sorted if b.limit_price_cents == best_clearing_price_cents]
        out_buys = [b for b in buys_sorted if b.limit_price_cents < best_clearing_price_cents]

        total_infra_buy_zat = sum(b.base_amount_zat for b in infra_buys)
        remaining_buy_zat = max(0, max_cleared_zat - total_infra_buy_zat)
        total_marginal_buy_zat = sum(b.base_amount_zat for b in marginal_buys)
        marginal_buy_allocations = allocate_exact_pro_rata(remaining_buy_zat, marginal_buys)

        buy_fills: List[MatchedFill] = []
        unfilled: List[str] = [b.intent_id for b in out_buys]

        # Fill inframarginal buyers 100%
        for b in infra_buys:
            quote_val = (b.base_amount_zat / 100_000_000.0) * clearing_price_usd
            buy_fills.append(MatchedFill(
                intent_id=b.intent_id,
                direction=b.direction,
                original_zat=b.base_amount_zat,
                filled_zat=b.base_amount_zat,
                clearing_price_usd=clearing_price_usd,
                quote_filled_usd=quote_val,
                shielded_address=b.shielded_address,
                fill_percentage=100.0,
                is_marginal=False
            ))

        # Fill marginal buyers with an integer-exact pro-rata allocation.
        for b in marginal_buys:
            filled_zat = marginal_buy_allocations[b.intent_id]
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
                    fill_percentage=(filled_zat / b.base_amount_zat) * 100.0,
                    is_marginal=True
                ))
            else:
                unfilled.append(b.intent_id)

        # 2. Sellers:
        # - Inframarginal: limit_price < P* -> 100% filled
        # - Marginal: limit_price == P* -> prorated on remaining volume
        # - Out-of-money: limit_price > P* -> 0% filled
        infra_sells = [s for s in sells_sorted if s.limit_price_cents < best_clearing_price_cents]
        marginal_sells = [s for s in sells_sorted if s.limit_price_cents == best_clearing_price_cents]
        out_sells = [s for s in sells_sorted if s.limit_price_cents > best_clearing_price_cents]

        total_infra_sell_zat = sum(s.base_amount_zat for s in infra_sells)
        remaining_sell_zat = max(0, max_cleared_zat - total_infra_sell_zat)
        total_marginal_sell_zat = sum(s.base_amount_zat for s in marginal_sells)
        marginal_sell_allocations = allocate_exact_pro_rata(remaining_sell_zat, marginal_sells)

        sell_fills: List[MatchedFill] = []
        for s in out_sells:
            unfilled.append(s.intent_id)

        # Fill inframarginal sellers 100%
        for s in infra_sells:
            quote_val = (s.base_amount_zat / 100_000_000.0) * clearing_price_usd
            sell_fills.append(MatchedFill(
                intent_id=s.intent_id,
                direction=s.direction,
                original_zat=s.base_amount_zat,
                filled_zat=s.base_amount_zat,
                clearing_price_usd=clearing_price_usd,
                quote_filled_usd=quote_val,
                shielded_address=s.shielded_address,
                fill_percentage=100.0,
                is_marginal=False
            ))

        # Fill marginal sellers with an integer-exact pro-rata allocation.
        for s in marginal_sells:
            filled_zat = marginal_sell_allocations[s.intent_id]
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
                    fill_percentage=(filled_zat / s.base_amount_zat) * 100.0,
                    is_marginal=True
                ))
            else:
                unfilled.append(s.intent_id)

        filled_buy_zat = sum(fill.filled_zat for fill in buy_fills)
        filled_sell_zat = sum(fill.filled_zat for fill in sell_fills)
        if filled_buy_zat != max_cleared_zat or filled_sell_zat != max_cleared_zat:
            raise RuntimeError(
                "FBA integer fill allocation is not balanced: "
                f"target={max_cleared_zat}, buys={filled_buy_zat}, sells={filled_sell_zat}"
            )

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
