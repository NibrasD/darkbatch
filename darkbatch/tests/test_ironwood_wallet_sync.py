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
