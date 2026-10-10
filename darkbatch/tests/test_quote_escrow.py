import pytest

from copy import deepcopy

from darkbatch.settlement.quote_escrow import (
    QuoteEscrowError,
    quote_escrow_batch_arrays,
    quote_escrow_data_hash,
)


def _plan():
    return {
        "epoch_id": 17,
        "clearing_price_usd": 1.25,
        "quote_total_micro": 300,
        "buy_fills": [
            {"intent_id": "b-2", "shielded_address": "zs2", "quote_address": "0x0000000000000000000000000000000000000022", "filled_zat": 200, "quote_amount_micro": 200},
            {"intent_id": "b-1", "shielded_address": "zs1", "quote_address": "0x0000000000000000000000000000000000000011", "filled_zat": 100, "quote_amount_micro": 100},
        ],
        "sell_fills": [
            {"intent_id": "s-2", "shielded_address": "zs4", "quote_address": "0x0000000000000000000000000000000000000044", "filled_zat": 200, "quote_amount_micro": 200},
            {"intent_id": "s-1", "shielded_address": "zs3", "quote_address": "0x0000000000000000000000000000000000000033", "filled_zat": 100, "quote_amount_micro": 100},
        ],
    }


def test_escrow_arrays_are_sorted_in_contract_order():
    arrays = quote_escrow_batch_arrays(_plan())
    assert arrays["buyer_addresses"] == [
        "0x0000000000000000000000000000000000000011",
        "0x0000000000000000000000000000000000000022",
    ]
    assert arrays["buyer_amounts_micro"] == [100, 200]
    assert arrays["seller_addresses"] == [
        "0x0000000000000000000000000000000000000033",
        "0x0000000000000000000000000000000000000044",
    ]
    assert arrays["seller_amounts_micro"] == [100, 200]


def test_escrow_data_hash_is_stable_under_fill_order_and_changes_with_payouts():
    plan = _plan()
    original = quote_escrow_data_hash(plan)
    assert len(original) == 64
    permuted = deepcopy(plan)
    permuted["buy_fills"].reverse()
    permuted["sell_fills"].reverse()
    assert quote_escrow_data_hash(permuted) == original

    changed = deepcopy(plan)
    changed["sell_fills"][0]["quote_address"] = "0x0000000000000000000000000000000000000099"
    assert quote_escrow_data_hash(changed) != original


def test_escrow_data_hash_rejects_unbalanced_plan():
    plan = _plan()
    plan["sell_fills"][0]["quote_amount_micro"] = 199
    with pytest.raises(QuoteEscrowError, match="quote totals do not balance"):
        quote_escrow_data_hash(plan)
