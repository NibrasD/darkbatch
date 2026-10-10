import pytest

from darkbatch.settlement.local_pczt_agent import (
    AgentError,
    _allocate_pro_rata,
    _build_request,
    _solver_fee_zat,
)


def test_solver_fee_is_converted_to_integer_zatoshis():
    assert _solver_fee_zat("0.00001234") == 1234
    assert _solver_fee_zat(0) == 0
    with pytest.raises(AgentError, match="finite, non-negative"):
        _solver_fee_zat("-0.01")


def test_pro_rata_solver_fee_allocation_conserves_every_zatoshi():
    shares = _allocate_pro_rata(1001, [100000, 50000])
    assert shares == [667, 334]
    assert sum(shares) == 1001
    assert _allocate_pro_rata(0, [100, 200]) == [0, 0]


def test_local_agent_builds_separate_solver_fee_output_and_seller_allocation(tmp_path):
    key_file = tmp_path / "seller-spending-key.hex"
    key_file.write_text("not-read-by-request-preparer", encoding="utf-8")
    txid = "ab" * 32
    path = ["00" * 32 for _ in range(32)]
    seller = "seller-ua"
    buyer = "buyer-ua"
    plan = {
        "epoch_id": 19,
        "clearing_price_usd": 1.25,
        "solver_fee_zec": "0.00001",
        "buy_fills": [
            {"intent_id": "buy-1", "filled_zat": 100000, "shielded_address": buyer,
             "clearing_price_usd": 1.25}
        ],
        "sell_fills": [
            {"intent_id": "sell-1", "filled_zat": 100000, "shielded_address": seller,
             "clearing_price_usd": 1.25}
        ],
    }
    wallet_data = {
        seller: {
            "fvk_hex": "11" * 96,
            "spending_key_file": str(key_file),
            "change_address_raw_hex": "22" * 43,
            "spendable_notes": [{
                "txid": txid,
                "output_index": 0,
                "unspent": True,
                "locked": False,
                "spent": False,
                "pool": "ironwood",
                "confirmations": 2,
                "value_zat": 200000,
                "raw_address_hex": "33" * 43,
                "rho_hex": "44" * 32,
                "rseed_hex": "55" * 32,
                "merkle_position": 7,
                "merkle_path_hex": path,
            }],
        },
        buyer: {"address_raw_hex": "66" * 43},
    }
    fee_receiver = {"address_raw_hex": "77" * 43}
    request, signing_rows = _build_request(
        plan, wallet_data, "88" * 32, 4_500_100, fee_receiver
    )
    assert [o["value_zat"] for o in request["outputs"]] == [100000, 1000]
    assert request["solver_fee_output_zat"] == 1000
    assert request["solver_fee_output_index"] == 1
    assert request["solver_fee_output_address_raw_hex"] == "77" * 43
    assert request["change_outputs"][0]["seller_fill_zat"] == 101000
    assert len(request["inputs"]) == len(signing_rows) == 1
    assert sum(o["value_zat"] for o in request["outputs"]) == sum(
        c["seller_fill_zat"] for c in request["change_outputs"]
    )
