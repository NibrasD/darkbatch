import json
from pathlib import Path

import pytest

from darkbatch.settlement import ironwood_wallet_scan as scan


class FakeZebra:
    def testnet_info(self):
        return {"chain": "test", "blocks": 100}

    def block_hash(self, height):
        return "ab" * 32 if int(height) == 100 else f"{int(height):064x}"


def _state(path: Path, *, height=100, note_root=None):
    root = "cc" * 32
    note = {
        "note_id": f"{height}:" + "dd" * 32 + ":1",
        "received_height": 90,
        "txid": "dd" * 32,
        "action_index": 1,
        "raw_address_hex": "33" * 43,
        "value_zat": 150_000,
        "rho_hex": "44" * 32,
        "rseed_hex": "55" * 32,
        "cmx_hex": "66" * 32,
        "nullifier_hex": "77" * 32,
        "memo_hex": "",
        "status": "UNSPENT",
        "witness_state_hex": "aabb",
        "witness_position": 9,
        "witness_auth_path_hex": ["88" * 32 for _ in range(32)],
        "witness_root_hex": note_root or root,
    }
    path.write_text(json.dumps({
        "schema_version": scan.STATE_SCHEMA_VERSION,
        "network": "testnet",
        "pool": "ironwood",
        "checkpoint_height": height,
        "checkpoint_hash": "ab" * 32,
        "height": height,
        "block_hash": "ab" * 32,
        "tree_state_hex": "ef",
        "tree_root_hex": root,
        "tracked_notes": [note],
    }), encoding="utf-8")
    return root


def _mock_rust(monkeypatch):
    def fake(command, request, binary_path=None):
        if command == "export-ironwood-fvk-stdin":
            return {"status": "LOCAL_FVK_EXPORTED", "network": "testnet", "full_viewing_key_hex": "11" * 96}
        if command == "derive-ironwood-address-stdin":
            index = request["address_index"]
            return {
                "status": "DERIVED_TESTNET_ADDRESS",
                "network": "testnet",
                "unified_address": "u1-example-wallet",
                "raw_ironwood_receiver_hex": ("22" if index == 0 else "99") * 43,
            }
        raise AssertionError(command)
    monkeypatch.setattr(scan, "_run_rust_json", fake)


def test_inventory_exports_only_real_scanned_notes_and_current_witnesses(tmp_path, monkeypatch):
    state_path = tmp_path / "wallet-state.json"
    key_path = tmp_path / "spending-key.hex"
    key_path.write_text("aa" * 32, encoding="ascii")
    _state(state_path)
    _mock_rust(monkeypatch)

    result = scan.create_wallet_inventory([{
        "state_path": str(state_path),
        "spending_key_file": str(key_path),
        "shielded_address": "u1-example-wallet",
        "address_index": 0,
        "change_index": 1,
    }], rpc=FakeZebra())

    assert result["schema"] == "darkbatch.ironwood-wallet-inventory.v1"
    assert result["network"] == "testnet"
    assert result["sync_status"] == "SYNCED"
    assert result["tip_height"] == result["anchor_height"] == 100
    wallet = result["wallets"]["u1-example-wallet"]
    assert wallet["fvk_hex"] == "11" * 96
    assert wallet["address_raw_hex"] == "22" * 43
    assert wallet["change_address_raw_hex"] == "99" * 43
    assert wallet["spendable_notes"][0]["txid"] == "dd" * 32
    assert wallet["spendable_notes"][0]["output_index"] == 1
    assert len(wallet["spendable_notes"][0]["merkle_path_hex"]) == 32
    assert "aa" * 32 not in json.dumps(result)


def test_inventory_refuses_wallet_state_behind_live_tip(tmp_path, monkeypatch):
    state_path = tmp_path / "wallet-state.json"
    key_path = tmp_path / "spending-key.hex"
    key_path.write_text("aa" * 32, encoding="ascii")
    _state(state_path, height=99)
    _mock_rust(monkeypatch)

    with pytest.raises(RuntimeError, match="not synced to the current canonical Zebra tip"):
        scan.create_wallet_inventory([{
            "state_path": str(state_path),
            "spending_key_file": str(key_path),
            "shielded_address": "u1-example-wallet",
            "address_index": 0,
            "change_index": 1,
        }], rpc=FakeZebra())


def test_inventory_refuses_stale_merkle_witness(tmp_path, monkeypatch):
    state_path = tmp_path / "wallet-state.json"
    key_path = tmp_path / "spending-key.hex"
    key_path.write_text("aa" * 32, encoding="ascii")
    _state(state_path, note_root="ee" * 32)
    _mock_rust(monkeypatch)

    with pytest.raises(RuntimeError, match="no witness for the current anchor"):
        scan.create_wallet_inventory([{
            "state_path": str(state_path),
            "spending_key_file": str(key_path),
            "shielded_address": "u1-example-wallet",
            "address_index": 0,
            "change_index": 1,
        }], rpc=FakeZebra())


def test_inventory_requires_distinct_wallet_configs(tmp_path, monkeypatch):
    state_path = tmp_path / "wallet-state.json"
    key_path = tmp_path / "spending-key.hex"
    key_path.write_text("aa" * 32, encoding="ascii")
    _state(state_path)
    _mock_rust(monkeypatch)
    config = {
        "state_path": str(state_path),
        "spending_key_file": str(key_path),
        "shielded_address": "u1-example-wallet",
        "address_index": 0,
        "change_index": 1,
    }

    with pytest.raises(RuntimeError, match="non-empty and unique"):
        scan.create_wallet_inventory([config, config], rpc=FakeZebra())
