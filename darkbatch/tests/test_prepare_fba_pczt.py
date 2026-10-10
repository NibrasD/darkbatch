import pytest

from darkbatch.settlement.prepare_fba_pczt import build_pczt_request


def _wallet_data():
    fvk = "11" * 96
    return {
        "target_height": 4_135_000,
        "ironwood_anchor_hex": "aa" * 32,
        "inputs": [
            {
                "owner_shielded_address": "seller-ua",
                "fvk_hex": fvk,
                "raw_address_hex": "22" * 43,
                "value_zat": 200_000,
                "rho_hex": "33" * 32,
                "rseed_hex": "44" * 32,
                "merkle_position": 7,
                "merkle_path_hex": ["00" * 32 for _ in range(32)],
            }
        ],
        "buyer_receivers": {
            "buyer-intent": {
                "address_raw_hex": "55" * 43,
                "memo_hex": "",
            }
        },
        "seller_change_receivers": {
            "seller-ua": {
                "fvk_hex": fvk,
                "address_raw_hex": "66" * 43,
            }
        },
        "solver_fee_receiver": {
            "address_raw_hex": "77" * 43,
            "memo_hex": "",
        },
    }


def _fills():
    return {
        "epoch_id": 19,
        "buy_fills": [
            {
                "intent_id": "buyer-intent",
                "filled_zat": 100_000,
                "shielded_address": "buyer-ua",
            }
        ],
        "sell_fills": [
            {
                "intent_id": "seller-intent",
                "filled_zat": 100_000,
                "shielded_address": "seller-ua",
            }
        ],
        "solver_fee_zat": 1_000,
    }


def test_fba_request_maps_buyer_output_seller_fill_and_fee_conservatively():
    request = build_pczt_request(_fills(), _wallet_data())

    assert len(request["outputs"]) == 2
    assert request["outputs"][0]["value_zat"] == 100_000
    assert request["outputs"][1]["value_zat"] == 1_000
    assert sum(o["value_zat"] for o in request["outputs"]) == 101_000
    assert len(request["change_outputs"]) == 1
    change = request["change_outputs"][0]
    assert change["value_zat"] is None
    assert change["seller_fill_zat"] == 101_000
    assert sum(i["value_zat"] for i in request["inputs"]) == 200_000
    assert "owner_shielded_address" not in request["inputs"][0]


def test_fba_request_rejects_unbalanced_buy_and_sell_fills():
    fills = _fills()
    fills["sell_fills"][0]["filled_zat"] = 99_999
    with pytest.raises(ValueError, match="unbalanced FBA result"):
        build_pczt_request(fills, _wallet_data())


def test_fba_request_requires_fee_recipient_when_solver_fee_is_nonzero():
    wallet = _wallet_data()
    wallet.pop("solver_fee_receiver")
    with pytest.raises(ValueError, match="solver_fee_receiver is missing"):
        build_pczt_request(_fills(), wallet)


def test_fba_request_rejects_missing_private_spendable_notes():
    wallet = _wallet_data()
    wallet["inputs"] = []
    with pytest.raises(ValueError, match="real spendable note inputs"):
        build_pczt_request(_fills(), wallet)
