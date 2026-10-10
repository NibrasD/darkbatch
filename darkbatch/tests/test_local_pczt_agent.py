import json
from pathlib import Path

import pytest

from darkbatch.settlement.local_pczt_agent import (
    AgentError,
    _allocate_pro_rata,
    _build_request,
    _run_full_pczt,
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


def test_local_pczt_funding_retry_is_iterative_and_rebuilds_signing_indexes(tmp_path, monkeypatch):
    key_file = tmp_path / "seller-spending-key.hex"
    key_file.write_text("local-test-key-file", encoding="utf-8")
    first = {
        "_id": ("ab" * 32, 0), "_value": 150_000,
        "raw_address_hex": "11" * 43, "rho_hex": "22" * 32,
        "rseed_hex": "33" * 32, "_position": 0, "_path": ["44" * 32 for _ in range(32)],
    }
    second = {
        "_id": ("cd" * 32, 1), "_value": 150_000,
        "raw_address_hex": "55" * 43, "rho_hex": "66" * 32,
        "rseed_hex": "77" * 32, "_position": 1, "_path": ["88" * 32 for _ in range(32)],
    }
    owner = {
        "fvk_hex": "99" * 96,
        "spending_key_file": key_file,
        "selected": [first],
        "selected_value": first["_value"],
        "candidates": [first, second],
    }
    request = {
        "target_height": 4_500_100,
        "ironwood_anchor_hex": "aa" * 32,
        "inputs": [],
        "outputs": [{"value_zat": 100}],
        "solver_fee_output_zat": 0,
        "solver_fee_output_address_raw_hex": "",
        "change_outputs": [{"seller_fill_zat": 100}],
    }
    calls = {"build": 0, "sign": 0}
    def fake_run_cli(binary, args, *, cwd, timeout=900):
        command = args[0]
        if command == "build-fba-pczt-local":
            calls["build"] += 1
            if calls["build"] == 1:
                raise AgentError("insufficient input to cover their allocated network fee")
            submitted = json.loads(Path(args[1]).read_text(encoding="utf-8"))
            assert len(submitted["inputs"]) == 2
            report = {
                "status": "FBA_PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES",
                "recipient_total_zat": 100,
                "buyer_output_total_zat": 100,
                "solver_fee_output_zat": 0,
                "solver_fee_output_address_raw_hex": "",
                "seller_fill_total_zat": 100,
                "ironwood_spend_action_indexes": [0, 1],
            }
            Path(args[3]).write_text(json.dumps(report), encoding="utf-8")
        elif command == "sign-pczt-local":
            calls["sign"] += 1
        elif command == "prove-extract-pczt-local":
            Path(args[2]).write_text("abcd", encoding="ascii")
            Path(args[3]).write_text(json.dumps({
                "status": "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED",
                "network_confirmed": False,
                "broadcast_ready": True,
            }), encoding="utf-8")
        return ""
    monkeypatch.setattr("darkbatch.settlement.local_pczt_agent._run_cli", fake_run_cli)

    reports, raw_tx_hex = _run_full_pczt(
        Path("darkbatch_crypto/target/release/darkbatch_crypto"),
        tmp_path,
        request,
        [(owner, key_file)],
    )
    assert calls["build"] == 2
    assert calls["sign"] == 2
    assert len(request["inputs"]) == 2
    assert len(reports["build_report"]["ironwood_spend_action_indexes"]) == 2
    assert raw_tx_hex == "abcd"

