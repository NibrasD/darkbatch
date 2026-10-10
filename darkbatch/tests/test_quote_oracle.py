import pytest

from darkbatch.settlement.quote_escrow import QuoteEscrowError
from darkbatch.settlement.prepare_quote_escrow_batch import build_manifest, encode_open_batch_calldata
from darkbatch.settlement import quote_oracle


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


def test_open_batch_manifest_encodes_contract_abi_without_broadcast():
    import time
    from darkbatch.settlement.quote_escrow import _selector

    deadline = int(time.time()) + 600
    manifest = build_manifest(_plan(), "12" * 32, deadline)
    raw = bytes.fromhex(manifest["calldata_hex"].removeprefix("0x"))
    signature = "openBatch(bytes32,bytes32,address[],uint256[],address[],uint256[],uint256)"
    assert manifest["broadcast"] is False
    assert manifest["buyer_total_micro"] == manifest["seller_total_micro"] == 300
    assert raw[:4].hex() == _selector(signature)
    assert len(raw) == 4 + 224 + (4 * 96)
    assert int.from_bytes(raw[4 + 64:4 + 96], "big") == 224
    assert int.from_bytes(raw[4 + 96:4 + 128], "big") == 320
    assert int.from_bytes(raw[4 + 128:4 + 160], "big") == 416
    assert int.from_bytes(raw[4 + 160:4 + 192], "big") == 512
    assert int.from_bytes(raw[4 + 192:4 + 224], "big") == deadline


def test_open_batch_manifest_requires_future_deadline():
    with pytest.raises(ValueError, match="future Unix timestamp"):
        build_manifest(_plan(), "12" * 32, 1)


def test_zebra_oracle_refuses_non_zebra_node(monkeypatch):
    calls = []

    def fake_rpc(method, params):
        calls.append(method)
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": 4_500_200}
        if method == "getnetworkinfo":
            return {"subversion": "/zcashd:6.0.0/"}
        raise AssertionError("must fail before querying transaction")
    monkeypatch.setattr(quote_oracle, "_zcash_rpc", fake_rpc)
    with pytest.raises(quote_oracle.OracleError, match="does not identify itself as Zebra"):
        quote_oracle.verify_zebra_confirmation("ab" * 32, 2)
    assert calls == ["getblockchaininfo", "getnetworkinfo"]


def test_zebra_oracle_requires_confirmation_depth(monkeypatch):
    def fake_rpc(method, params):
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": 4_500_200}
        if method == "getnetworkinfo":
            return {"subversion": "/Zebra:2.0.0/"}
        if method == "getrawtransaction":
            return {"txid": "ab" * 32, "blockhash": "cd" * 32, "confirmations": 1}
        if method == "getblockheader":
            return {"hash": "cd" * 32, "height": 4_500_199}
        raise AssertionError(method)
    monkeypatch.setattr(quote_oracle, "_zcash_rpc", fake_rpc)
    with pytest.raises(quote_oracle.OracleError, match="required"):
        quote_oracle.verify_zebra_confirmation("ab" * 32, 2)


def test_zebra_oracle_accepts_matching_confirmed_transaction(monkeypatch):
    def fake_rpc(method, params):
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": 4_500_200}
        if method == "getnetworkinfo":
            return {"subversion": "/Zebra:2.0.0/"}
        if method == "getrawtransaction":
            return {"txid": "ab" * 32, "blockhash": "cd" * 32, "confirmations": 2}
        if method == "getblockheader":
            return {"hash": "cd" * 32, "height": 4_500_199}
        raise AssertionError(method)
    monkeypatch.setattr(quote_oracle, "_zcash_rpc", fake_rpc)
    result = quote_oracle.verify_zebra_confirmation("ab" * 32, 2)
    assert result["txid"] == "ab" * 32
    assert result["block_hash"] == "cd" * 32
    assert result["confirmations"] == 2
