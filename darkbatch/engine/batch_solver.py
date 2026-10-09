"""
Deterministic uniform-price Frequent Batch Auction matching.

This module computes off-chain matches only. It is not a wallet, a proof system,
or a Zcash consensus validator. Allocations conserve the exact matched zatoshi
amount on both sides; price priority applies at each side's marginal cutoff.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import groupby
import time
from typing import List

from darkbatch.core.intent import SwapOrderIntent, OrderDirection

ZATOSHIS_PER_ZEC = 100_000_000


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


class BatchAuctionSolver:
    """
    Maximize matched volume at a uniform price, then allocate that exact volume
    by price priority. Orders tied at the rationing cutoff are allocated pro-rata
    using deterministic largest-remainder rounding in integer zatoshis.
    """

    def __init__(self, solver_fee_bps: int = 10):
        if not 0 <= solver_fee_bps <= 10_000:
            raise ValueError("solver_fee_bps must be between 0 and 10000.")
        self.solver_fee_bps = solver_fee_bps

    @staticmethod
    def _empty_result(epoch_id: int, start_time: float, intents: List[SwapOrderIntent]) -> BatchClearResult:
        return BatchClearResult(
            epoch_id=epoch_id,
            clearing_price_usd=0.0,
            total_cleared_zec=0.0,
            total_cleared_usd=0.0,
            unfilled_intents=[i.intent_id for i in intents],
            solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0,
        )

    @staticmethod
    def _pro_rata(group: list[SwapOrderIntent], target_zat: int) -> dict[str, int]:
        """Allocate target_zat exactly with largest-remainder rounding and stable ties."""
        total = sum(order.base_amount_zat for order in group)
        if not 0 <= target_zat <= total:
            raise ValueError("Pro-rata target must be within the marginal group total.")
        if total == 0 or target_zat == 0:
            return {order.intent_id: 0 for order in group}
        allocations: dict[str, int] = {}
        remainders: list[tuple[int, str]] = []
        for order in group:
            numerator = order.base_amount_zat * target_zat
            allocated, remainder = divmod(numerator, total)
            allocations[order.intent_id] = allocated
            remainders.append((remainder, order.intent_id))
        leftover = target_zat - sum(allocations.values())
        # The number of leftover zatoshis is less than the number of orders.
        # A stable intent-id tie break makes the result independent of input ordering.
        for _, intent_id in sorted(remainders, key=lambda item: (-item[0], item[1]))[:leftover]:
            allocations[intent_id] += 1
        assert sum(allocations.values()) == target_zat
        return allocations

    @classmethod
    def _allocate_side(
        cls,
        orders: list[SwapOrderIntent],
        target_zat: int,
        direction: OrderDirection,
        price_usd: float,
    ) -> tuple[list[MatchedFill], list[str]]:
        """
        Allocate exactly target_zat to eligible orders in price priority.
        Only the price group cut by the remaining quantity is pro-rated.
        """
        reverse = direction == OrderDirection.BUY_ZEC
        sorted_orders = sorted(
            orders,
            key=lambda order: ((-order.limit_price_cents) if reverse else order.limit_price_cents, order.intent_id),
        )
        remaining = target_zat
        fills: list[MatchedFill] = []
        fully_unfilled: list[str] = []

        for _, grouped in groupby(sorted_orders, key=lambda order: order.limit_price_cents):
            group = list(grouped)
            group_total = sum(order.base_amount_zat for order in group)
            if remaining <= 0:
                fully_unfilled.extend(order.intent_id for order in group)
                continue
            if group_total <= remaining:
                allocations = {order.intent_id: order.base_amount_zat for order in group}
                was_rationed = False
            else:
                allocations = cls._pro_rata(group, remaining)
                was_rationed = True

            for order in group:
                amount = allocations[order.intent_id]
                if amount <= 0:
                    fully_unfilled.append(order.intent_id)
                    continue
                quote_value = (amount / ZATOSHIS_PER_ZEC) * price_usd
                fills.append(
                    MatchedFill(
                        intent_id=order.intent_id,
                        direction=direction,
                        original_zat=order.base_amount_zat,
                        filled_zat=amount,
                        clearing_price_usd=price_usd,
                        quote_filled_usd=quote_value,
                        shielded_address=order.shielded_address,
                        fill_percentage=(amount / order.base_amount_zat) * 100.0,
                        is_marginal=was_rationed,
                    )
                )
            remaining -= min(group_total, remaining)

        if remaining != 0:
            raise RuntimeError(
                f"Allocation invariant failed for {direction.value}: {remaining} zatoshis remain."
            )
        return fills, fully_unfilled

    def solve(self, epoch_id: int, intents: List[SwapOrderIntent]) -> BatchClearResult:
        start_time = time.perf_counter()
        invalid_ids = [order.intent_id for order in intents if not order.verify_signature()]
        valid_intents = [order for order in intents if order.verify_signature()]
        buys = [order for order in valid_intents if order.direction == OrderDirection.BUY_ZEC]
        sells = [order for order in valid_intents if order.direction == OrderDirection.SELL_ZEC]

        if not buys or not sells:
            result = self._empty_result(epoch_id, start_time, valid_intents)
            result.unfilled_intents.extend(invalid_ids)
            return result

        highest_bid = max(order.limit_price_cents for order in buys)
        lowest_ask = min(order.limit_price_cents for order in sells)
        if highest_bid < lowest_ask:
            result = self._empty_result(epoch_id, start_time, valid_intents)
            result.unfilled_intents.extend(invalid_ids)
            return result

        candidate_prices = sorted({
            order.limit_price_cents for order in buys + sells
        })
        max_volume = 0
        volume_maximizing_prices: list[int] = []

        for price_cents in candidate_prices:
            demand = sum(
                order.base_amount_zat for order in buys
                if order.limit_price_cents >= price_cents
            )
            supply = sum(
                order.base_amount_zat for order in sells
                if order.limit_price_cents <= price_cents
            )
            volume = min(demand, supply)
            if volume > max_volume:
                max_volume = volume
                volume_maximizing_prices = [price_cents]
            elif volume == max_volume and volume > 0:
                volume_maximizing_prices.append(price_cents)

        if max_volume <= 0 or not volume_maximizing_prices:
            result = self._empty_result(epoch_id, start_time, valid_intents)
            result.unfilled_intents.extend(invalid_ids)
            return result

        # For a discrete order book, the maximized volume often holds over a price
        # interval. Use the midpoint of the full maximizing plateau, not iterative
        # pairwise midpoint rounding (which is order-biased).
        low_cents = min(volume_maximizing_prices)
        high_cents = max(volume_maximizing_prices)
        # Price limits are integer cents, so keep P* on the same tick grid.
        # Flooring an exact half-cent tie is deterministic and avoids creating
        # a clearing price users could not have submitted.
        clearing_price_cents = (low_cents + high_cents) // 2
        clearing_price_usd = clearing_price_cents / 100.0

        eligible_buys = [
            order for order in buys if order.limit_price_cents >= clearing_price_cents
        ]
        eligible_sells = [
            order for order in sells if order.limit_price_cents <= clearing_price_cents
        ]
        buy_fills, unfilled_buys = self._allocate_side(
            eligible_buys, max_volume, OrderDirection.BUY_ZEC, clearing_price_usd
        )
        sell_fills, unfilled_sells = self._allocate_side(
            eligible_sells, max_volume, OrderDirection.SELL_ZEC, clearing_price_usd
        )

        if sum(fill.filled_zat for fill in buy_fills) != max_volume:
            raise RuntimeError("Buyer fill total does not equal maximized clearing volume.")
        if sum(fill.filled_zat for fill in sell_fills) != max_volume:
            raise RuntimeError("Seller fill total does not equal maximized clearing volume.")

        allocated_ids = {fill.intent_id for fill in buy_fills + sell_fills}
        unfilled = set(unfilled_buys + unfilled_sells + invalid_ids)
        # Orders excluded by the clearing price (out of the money) are also unfilled.
        unfilled.update(
            order.intent_id for order in valid_intents
            if order.intent_id not in allocated_ids
        )

        total_cleared_zec = max_volume / ZATOSHIS_PER_ZEC
        total_cleared_usd = total_cleared_zec * clearing_price_usd
        solver_fee_zec = total_cleared_zec * (self.solver_fee_bps / 10_000.0)
        return BatchClearResult(
            epoch_id=epoch_id,
            clearing_price_usd=clearing_price_usd,
            total_cleared_zec=total_cleared_zec,
            total_cleared_usd=total_cleared_usd,
            buy_fills=buy_fills,
            sell_fills=sell_fills,
            unfilled_intents=sorted(unfilled),
            solver_fee_zec=solver_fee_zec,
            solver_execution_time_ms=(time.perf_counter() - start_time) * 1000.0,
        )
