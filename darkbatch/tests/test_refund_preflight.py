import pytest
from fastapi import HTTPException

from darkbatch.api import server
from darkbatch.settlement.quote_escrow import quote_plan_hash, quote_escrow_data_hash


def _plan():
    return {
        "schema": "darkbatch.fba-local-pczt-plan.v1",
        "status": "LOCAL_PCZT_REQUIRED",
        "epoch_id": 17,
        "clearing_price_usd": 1.25,
        "quote_total_micro": 300,
        "buy_fills": [
            {
                "intent_id": "buy-1",
                "shielded_address": "test-buyer-1",
                "quote_address": "0x0000000000000000000000000000000000000011",
                "filled_zat": 100,
                "quote_amount_micro": 100,
            },
            {
                "intent_id": "buy-2",
                "shielded_address": "test-buyer-2",
                "quote_address": "0x0000000000000000000000000000000000000022",
                "filled_zat": 200,
                "quote_amount_micro": 200,
            },
        ],
        "sell_fills": [
            {
                "intent_id": "sell-1",
                "shielded_address": "test-seller-1",
                "quote_address": "0x0000000000000000000000000000000000000033",
                "filled_zat": 100,
                "quote_amount_micro": 100,
            },
            {
                "intent_id": "sell-2",
                "shielded_address": "test-seller-2",
                "quote_address": "0x0000000000000000000000000000000000000044",
                "filled_zat": 200,
                "quote_amount_micro": 200,
            },
        ],
    }


def _configure_refund_preflight(monkeypatch, plan=None):
    plan = plan or _plan()
    monkeypatch.setenv("DARKBATCH_SETTLEMENT_TOKEN", "unit-test-token")
    monkeypatch.setattr(server, "get_active_epoch_id", lambda: 17)
    monkeypatch.setattr(server, "get_epoch_by_id", lambda _epoch_id: {"status": "ACTIVE", "tx_id": None})
    monkeypatch.setattr(server.TESTNET_ADAPTER, "broadcast_history", {})
    monkeypatch.setattr(server.SOLVER, "local_settlement_plans", {17: plan})
    plan_hash = quote_plan_hash(plan)
    expected_batch = "0x" + server._keccak256_hex(
        server._abi_word_uint(17) + bytes.fromhex(plan_hash)
    )
    return plan, expected_batch


def test_refund_preflight_allows_only_exact_active_plan_without_tracked_zec(monkeypatch):
    _plan_value, batch_id = _configure_refund_preflight(monkeypatch)
    request = server.QuoteRefundPreflightRequest(epoch_id=17, quote_batch_id=batch_id)

    result = server.preflight_expired_quote_refund(
        request, x_darkbatch_settlement_token="unit-test-token"
    )

    assert result["status"] == "REFUND_PREFLIGHT_PASSED"
    assert result["epoch_id"] == 17
    assert result["quote_batch_id"] == batch_id
    assert result["epoch_has_tracked_zec_tx"] is False
    assert result["operator_no_broadcast_attestation_required"] is True
    assert result["quote_escrow_data_hash"] == quote_escrow_data_hash(_plan())


def test_refund_preflight_refuses_an_epoch_that_already_has_a_zec_lifecycle(monkeypatch):
    _, batch_id = _configure_refund_preflight(monkeypatch)
    monkeypatch.setattr(
        server, "get_epoch_by_id",
        lambda _epoch_id: {"status": "ZEC_LEG_PENDING", "tx_id": "ab" * 32},
    )

    with pytest.raises(HTTPException) as exc:
        server.preflight_expired_quote_refund(
            server.QuoteRefundPreflightRequest(epoch_id=17, quote_batch_id=batch_id),
            x_darkbatch_settlement_token="unit-test-token",
        )
    assert exc.value.status_code == 409
    assert "refund is refused" in str(exc.value.detail)


def test_refund_preflight_refuses_a_batch_for_a_different_plan(monkeypatch):
    _, batch_id = _configure_refund_preflight(monkeypatch)
    wrong_batch = "0x" + "ff" * 32

    with pytest.raises(HTTPException) as exc:
        server.preflight_expired_quote_refund(
            server.QuoteRefundPreflightRequest(epoch_id=17, quote_batch_id=wrong_batch),
            x_darkbatch_settlement_token="unit-test-token",
        )
    assert exc.value.status_code == 409
    assert "does not match this epoch" in str(exc.value.detail)
