import json

import pytest

from darkbatch.settlement import ironwood_wallet_sync as wallet_sync


class FakeZebra:
    def __init__(self):
        self.tip = 4_134_010
        self.states = {
            4_134_009: "aa" * 32,
            4_134_010: "bb" * 32,
        }

    def testnet_info(self):
        return {"chain": "test", "blocks": self.tip}

    def block_hash(self, height):
        return f"{height:064x}"

    def treestate(self, block_hash):
        height = int(block_hash, 16)
        return {
            "height": height,
            "hash": block_hash,
            "final_state_hex": self.states[height],
        }

    def raw_block_hex(self, block_hash):
        return "ab" * 64


def test_wallet_scan_saves_canonical_progress_without_saving_spending_key(tmp_path, monkeypatch):
    rpc = FakeZebra()
    monkeypatch.setattr(wallet_sync, "_derive_tree_root", lambda tree_state_hex, binary_path=None: "cc" * 32)

    state_path = tmp_path / "wallet-state.json"
    wallet_sync.initialize_wallet_scan(
        state_path,
        start_height=4_134_009,
        rpc=rpc,
        binary_path="not-used-by-monkeypatch",
    )

    spending_key = "55" * 32

    def fake_scan(binary_path, *, request, timeout_seconds=900):
        assert request["network"] == "testnet"
        assert request["spending_key_hex"] == spending_key
        assert request["tree_state_hex"] == "aa" * 32
        assert request["expected_final_state_hex"] == "aa" * 32
        return {
            "status": "SCANNED_BLOCK",
            "height": 4_134_010,
            "block_hash": rpc.block_hash(4_134_010),
            "prev_block_hash": rpc.block_hash(4_134_009),
            "tree_state_hex": "bb" * 32,
            "tree_root_hex": "dd" * 32,
            "tracked_notes": [{
                "note_id": "4134010:" + "12" * 32 + ":0",
                "status": "UNSPENT",
                "value_zat": 20_000,
                "witness_state_hex": "ef",
                "witness_root_hex": "dd" * 32,
                "witness_position": 0,
                "witness_auth_path_hex": ["00" * 32] * 32,
            }],
            "new_note_ids": ["new-note-1"],
            "spent_note_ids": [],
        }

    monkeypatch.setattr(wallet_sync, "_scan_block_with_rust", fake_scan)
    result = wallet_sync.sync_wallet_scan(
        state_path,
        spending_key,
        rpc=rpc,
        binary_path="not-used-by-monkeypatch",
    )

    assert result["height"] == rpc.tip
    assert result["tree_state_hex"] == rpc.states[rpc.tip]
    assert result["tree_root_hex"] == "dd" * 32
    assert result["last_sync"]["scanned_blocks"] == 1
    assert result["last_sync"]["new_notes"] == 1
    serialized = state_path.read_text(encoding="utf-8")
    assert spending_key not in serialized
    assert result["tracked_notes"][0]["witness_root_hex"] == result["tree_root_hex"]


def test_build_accepts_standard_unified_address_and_forwards_it_to_official_builder(tmp_path, monkeypatch):
    rpc = FakeZebra()
    spending_key = "55" * 32
    state_path = tmp_path / "wallet-state.json"
    note = {
        "note_id": "n1",
        "status": "UNSPENT",
        "value_zat": 50_000,
        "raw_address_hex": "33" * 43,
        "nullifier_hex": "44" * 32,
        "rho_hex": "55" * 32,
        "rseed_hex": "66" * 32,
        "witness_state_hex": "ef",
        "witness_position": 1,
        "witness_auth_path_hex": ["00" * 32] * 32,
        "witness_root_hex": "dd" * 32,
    }
    state_path.write_text(json.dumps({
        "schema_version": wallet_sync.STATE_SCHEMA_VERSION,
        "network": "testnet",
        "pool": "ironwood",
        "height": rpc.tip,
        "block_hash": rpc.block_hash(rpc.tip),
        "tree_state_hex": rpc.states[rpc.tip],
        "tree_root_hex": "dd" * 32,
        "tracked_notes": [note],
    }), encoding="utf-8")
    monkeypatch.setattr(wallet_sync, "_derive_tree_root", lambda tree_state_hex, binary_path=None: "dd" * 32)

    captured = {}

    def fake_builder(request, *, binary_path=None, timeout_seconds=1800):
        captured["request"] = request
        return wallet_sync.BuiltIronwoodTransaction(
            txid="aa" * 32,
            raw_tx_hex="0011",
            raw_tx_bytes_len=2,
            target_height=rpc.tip + 1,
            consensus_branch_id=0x37A5165B,
            version_group_id=0xD884B698,
            transaction_version=6,
        )

    monkeypatch.setattr(wallet_sync, "build_ironwood_transaction", fake_builder)
    result = wallet_sync.build_transaction_from_notes(
        state_path,
        spending_key,
        ["n1"],
        [{"recipient_address": "u1-example-unified-address", "value_zat": 10_000}],
        rpc=rpc,
        binary_path="not-used-by-fake-builder",
    )

    output = captured["request"]["outputs"][0]
    assert output["recipient_address"] == "u1-example-unified-address"
    assert "recipient_address_raw_hex" not in output
    assert result.txid == "aa" * 32


def test_wallet_scan_refuses_a_checkpoint_that_is_not_canonical(tmp_path, monkeypatch):
    rpc = FakeZebra()
    monkeypatch.setattr(wallet_sync, "_derive_tree_root", lambda tree_state_hex, binary_path=None: "cc" * 32)
    state_path = tmp_path / "wallet-state.json"
    wallet_sync.initialize_wallet_scan(
        state_path,
        start_height=4_134_009,
        rpc=rpc,
        binary_path="not-used-by-monkeypatch",
    )
    rpc.block_hash = lambda height: "ff" * 32 if height == 4_134_009 else f"{height:064x}"

    with pytest.raises(RuntimeError, match="not on the node's current canonical chain"):
        wallet_sync.sync_wallet_scan(
            state_path,
            "55" * 32,
            rpc=rpc,
            binary_path="not-used-by-monkeypatch",
        )



def test_transaction_status_uses_live_rpc_confirmation_count(monkeypatch):
    txid = "ab" * 32

    class FakeRpc:
        def call(self, method, params):
            assert method == "getrawtransaction"
            assert params == [txid, True]
            return {
                "txid": txid,
                "confirmations": 2,
                "blockhash": "cd" * 32,
                "blocktime": 123,
                "height": 4_134_012,
            }

    result = wallet_sync.get_testnet_transaction_status(txid, rpc=FakeRpc())
    assert result["status"] == "MINED_CONFIRMED"
    assert result["confirmed"] is True
    assert result["confirmations"] == 2
    assert result["source"] == "live-zebra-rpc"


def test_transaction_status_does_not_infer_confirmation_from_zero_confirmations():
    txid = "ef" * 32

    class FakeRpc:
        def call(self, method, params):
            return {"txid": txid, "confirmations": 0}

    result = wallet_sync.get_testnet_transaction_status(txid, rpc=FakeRpc())
    assert result["status"] == "BROADCAST_PENDING"
    assert result["confirmed"] is False
    assert result["confirmations"] == 0


def test_transaction_status_rejects_malformed_txid():
    with pytest.raises(RuntimeError, match="64 hexadecimal"):
        wallet_sync.get_testnet_transaction_status("not-a-txid", rpc=object())
