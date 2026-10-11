import pytest

from copy import deepcopy

from darkbatch.settlement import quote_escrow
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



def test_escrow_arrays_aggregate_multiple_fills_for_the_same_evm_wallet():
    plan = _plan()
    shared_buyer = "0x0000000000000000000000000000000000000011"
    shared_seller = "0x0000000000000000000000000000000000000033"
    plan["buy_fills"][0]["quote_address"] = shared_buyer
    plan["buy_fills"][1]["quote_address"] = shared_buyer
    plan["sell_fills"][0]["quote_address"] = shared_seller
    plan["sell_fills"][1]["quote_address"] = shared_seller

    arrays = quote_escrow_batch_arrays(plan)

    assert arrays["buyer_addresses"] == [shared_buyer]
    assert arrays["buyer_amounts_micro"] == [300]
    assert arrays["seller_addresses"] == [shared_seller]
    assert arrays["seller_amounts_micro"] == [300]
    assert len(quote_escrow_data_hash(plan)) == 64



def test_funded_batch_requires_two_canonical_evm_confirmations(monkeypatch):
    monkeypatch.setenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2")
    batch_id = "12" * 32
    plan_hash = "34" * 32
    event_topic = "56" * 32
    address = "0x00000000000000000000000000000000000000aa"
    log = {
        "address": address,
        "topics": ["0x" + event_topic, "0x" + batch_id],
        "data": "0x" + plan_hash,
        "blockNumber": "0xa",
        "removed": False,
    }
    tip = {"value": "0xb"}

    monkeypatch.setattr(quote_escrow, "_keccak256_hex", lambda _payload: event_topic)

    def fake_rpc(_url, method, params):
        if method == "eth_getLogs":
            assert params[0]["fromBlock"] == "0x1"
            assert params[0]["topics"] == ["0x" + event_topic, "0x" + batch_id]
            return [log]
        if method == "eth_blockNumber":
            return tip["value"]
        raise AssertionError(method)

    monkeypatch.setattr(quote_escrow, "_rpc", fake_rpc)
    passed = quote_escrow._verify_funded_event_finality(
        batch_id, plan_hash, 1, "https://evm.invalid", address
    )
    assert passed["funding_event_block"] == 10
    assert passed["funding_event_confirmations"] == 2

    tip["value"] = "0xa"
    with pytest.raises(QuoteEscrowError, match="confirmation\(s\)"):
        quote_escrow._verify_funded_event_finality(
            batch_id, plan_hash, 1, "https://evm.invalid", address
        )


def test_funded_event_requires_matching_plan_hash(monkeypatch):
    monkeypatch.setenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2")
    batch_id = "12" * 32
    address = "0x00000000000000000000000000000000000000aa"
    log = {
        "address": address,
        "topics": ["0x" + "56" * 32, "0x" + batch_id],
        "data": "0x" + "99" * 32,
        "blockNumber": "0xa",
    }
    monkeypatch.setattr(quote_escrow, "_keccak256_hex", lambda _payload: "56" * 32)
    monkeypatch.setattr(
        quote_escrow,
        "_rpc",
        lambda _url, method, _params: [log] if method == "eth_getLogs" else "0xb",
    )
    with pytest.raises(QuoteEscrowError, match="plan hash"):
        quote_escrow._verify_funded_event_finality(
            batch_id, "34" * 32, 1, "https://evm.invalid", address
        )
