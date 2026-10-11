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


def _install_oracle_resume_mocks(monkeypatch, *, batch_status):
    from eth_account import Account

    plan = _plan()
    txid = "ab" * 32
    block_hash = "cd" * 32
    batch_id = "12" * 32
    plan_hash = "55" * 32
    data_hash = "66" * 32
    monkeypatch.setenv("DARKBATCH_SETTLEMENT_TOKEN", "test-token")
    monkeypatch.setenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "0x" + "00" * 31 + "01")
    monkeypatch.setattr(quote_oracle, "verify_zebra_confirmation", lambda *_: {
        "txid": txid, "block_hash": block_hash, "confirmations": 2, "block_height": 9,
        "tip_height": 10, "network": "test", "zebra_subversion": "/Zebra:test/",
    })
    monkeypatch.setattr(quote_oracle, "_coordinator_transaction", lambda *_: {})
    monkeypatch.setattr(quote_oracle, "verify_epoch_association", lambda *_: None)
    monkeypatch.setattr(quote_oracle, "quote_plan_hash", lambda _plan: plan_hash)
    monkeypatch.setattr(quote_oracle, "quote_escrow_data_hash", lambda _plan: data_hash)
    monkeypatch.setattr(quote_oracle, "_config", lambda: {
        "rpc_url": "https://evm.invalid", "chain_id": 1,
        "escrow_address": "0x00000000000000000000000000000000000000ee",
    })
    monkeypatch.setattr(
        quote_oracle, "_oracle_address_from_contract",
        lambda _cfg: Account.from_key("0x" + "00" * 31 + "01").address,
    )
    batch = {
        "status_code": batch_status,
        "plan_hash": plan_hash,
        "escrow_data_hash": data_hash,
        "zec_txid": txid if batch_status in {quote_oracle.STATUS_ZEC_CONFIRMED, quote_oracle.STATUS_RELEASED} else "",
        "zec_block_hash": block_hash if batch_status in {quote_oracle.STATUS_ZEC_CONFIRMED, quote_oracle.STATUS_RELEASED} else "",
    }
    monkeypatch.setattr(quote_oracle, "_read_batch", lambda _batch_id: dict(batch))
    resume = {
        "epoch_id": 17,
        "batch_id": "0x" + batch_id,
        "plan_hash": plan_hash,
        "escrow_data_hash": data_hash,
        "zec": {"txid": txid},
    }
    return plan, batch_id, txid, resume


def test_resume_pending_attestation_polls_same_tx_without_rebroadcast(monkeypatch):
    plan, batch_id, txid, resume = _install_oracle_resume_mocks(
        monkeypatch, batch_status=quote_oracle.STATUS_FUNDED
    )
    old_hash = "0x" + "77" * 32
    resume.update({
        "status": "ZEC_CONFIRMED_ON_ZEBRA_EVM_ATTESTATION_PENDING",
        "attestation_transaction": {
            "status": "EVM_TRANSACTION_PENDING",
            "transaction_hash": old_hash,
        },
    })
    waited = []
    monkeypatch.setattr(
        quote_oracle, "_wait_for_evm_receipt",
        lambda tx_hash, cfg, wait_seconds: (
            waited.append((tx_hash, wait_seconds))
            or {"status": "EVM_TRANSACTION_PENDING", "transaction_hash": tx_hash}
        ),
    )
    monkeypatch.setattr(
        quote_oracle, "_send_evm_transaction",
        lambda *_args, **_kwargs: pytest.fail("must not broadcast a replacement attestation"),
    )

    result = quote_oracle.run(
        "http://127.0.0.1:8000", 17, batch_id, txid, plan, 2, True, True, 20,
        resume_result=resume,
    )

    assert result["status"] == "ZEC_CONFIRMED_ON_ZEBRA_EVM_ATTESTATION_PENDING"
    assert result["attestation_transaction"]["transaction_hash"] == old_hash
    assert waited == [(old_hash, 20)]


def test_resume_pending_usdc_release_polls_same_tx_without_rebroadcast(monkeypatch):
    plan, batch_id, txid, resume = _install_oracle_resume_mocks(
        monkeypatch, batch_status=quote_oracle.STATUS_ZEC_CONFIRMED
    )
    old_hash = "0x" + "88" * 32
    resume.update({
        "status": "ZEC_ATTESTED_USDC_RELEASE_PENDING",
        "attestation_transaction": {"status": "EVM_TRANSACTION_CONFIRMED", "transaction_hash": "0x" + "99" * 32},
        "release_transaction": {
            "status": "EVM_TRANSACTION_PENDING",
            "transaction_hash": old_hash,
        },
    })
    waited = []
    monkeypatch.setattr(
        quote_oracle, "_wait_for_evm_receipt",
        lambda tx_hash, cfg, wait_seconds: (
            waited.append((tx_hash, wait_seconds))
            or {"status": "EVM_TRANSACTION_PENDING", "transaction_hash": tx_hash}
        ),
    )
    monkeypatch.setattr(
        quote_oracle, "_send_evm_transaction",
        lambda *_args, **_kwargs: pytest.fail("must not broadcast a replacement USDC release"),
    )

    result = quote_oracle.run(
        "http://127.0.0.1:8000", 17, batch_id, txid, plan, 2, True, True, 20,
        resume_result=resume,
    )

    assert result["status"] == "ZEC_ATTESTED_USDC_RELEASE_PENDING"
    assert result["release_transaction"]["transaction_hash"] == old_hash
    assert waited == [(old_hash, 20)]


def test_released_escrow_recovery_preserves_original_release_hash(monkeypatch):
    plan, batch_id, txid, resume = _install_oracle_resume_mocks(
        monkeypatch, batch_status=quote_oracle.STATUS_RELEASED
    )
    release_hash = "0x" + "aa" * 32
    attestation_hash = "0x" + "bb" * 32
    resume.update({
        "status": "USDC_RELEASED",
        "attestation_transaction": {
            "status": "EVM_TRANSACTION_CONFIRMED",
            "transaction_hash": attestation_hash,
        },
        "release_transaction": {
            "status": "EVM_TRANSACTION_CONFIRMED",
            "transaction_hash": release_hash,
        },
    })
    monkeypatch.setattr(
        quote_oracle, "_send_evm_transaction",
        lambda *_args, **_kwargs: pytest.fail("an already released batch must not broadcast again"),
    )

    result = quote_oracle.run(
        "http://127.0.0.1:8000", 17, batch_id, txid, plan, 2, True, True, 20,
        resume_result=resume,
    )

    assert result["status"] == "USDC_RELEASED"
    assert result["release_transaction"]["transaction_hash"] == release_hash
    assert result["attestation_transaction"]["transaction_hash"] == attestation_hash



def _signed_state_fixture(tmp_path):
    from eth_account import Account

    raw = bytes.fromhex("01020304")
    tx_hash = "0x" + quote_oracle._keccak256_hex(raw)
    signer = Account.from_key("0x" + "00" * 31 + "01").address.lower()
    escrow = "0x00000000000000000000000000000000000000ee"
    context = {
        "epoch_id": 17,
        "batch_id": "0x" + "11" * 32,
        "zec_txid": "22" * 32,
        "zec_block_hash": "33" * 32,
        "plan_hash": "44" * 32,
        "escrow_data_hash": "55" * 32,
        "evm_chain_id": 1,
        "escrow_address": escrow,
        "oracle_address": signer,
    }
    state_path = tmp_path / "usdc-oracle-signed-txs.json"
    quote_oracle._write_transaction_state(state_path, {
        "schema": "darkbatch.evm-signed-transactions.v2",
        **context,
        "transactions": {
            "release": {
                "transaction_hash": tx_hash,
                "raw_transaction_hex": "0x" + raw.hex(),
                "status": "EVM_TRANSACTION_PENDING",
                "stage": "release",
                "from": signer,
                "to": escrow,
                "chain_id": 1,
                "nonce": 0,
                "calldata_hash": "0x" + quote_oracle._keccak256_hex(bytes.fromhex("1234")),
            }
        },
    })
    return state_path, context, tx_hash, "0x" + raw.hex()


def test_signed_evm_recovery_polls_existing_mempool_tx_without_new_nonce(tmp_path, monkeypatch):
    from eth_account import Account
    monkeypatch.setenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2")
    signer = Account.from_key("0x" + "00" * 31 + "01").address
    monkeypatch.setattr(Account, "recover_transaction", lambda _raw: signer)
    state_path, context, tx_hash, raw_hex = _signed_state_fixture(tmp_path)
    calls = []
    def fake_rpc(url, method, params):
        calls.append((method, params))
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getTransactionReceipt":
            if len([item for item in calls if item[0] == "eth_getTransactionReceipt"]) <= 2:
                return None
            return {"status": "0x1", "blockNumber": "0xf"}
        if method == "eth_getTransactionByHash":
            return {"hash": tx_hash}
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_sendRawTransaction":
            pytest.fail("an already-visible transaction must not be rebroadcast")
        raise AssertionError(method)
    monkeypatch.setattr(quote_oracle, "_rpc", fake_rpc)

    result = quote_oracle._recover_or_submit_signed_evm_transaction(
        "release", "0x1234", "0x" + "00" * 31 + "01",
        {"rpc_url": "https://evm.invalid", "chain_id": 1,
         "escrow_address": "0x00000000000000000000000000000000000000ee"},
        5, state_path, context,
    )

    assert result["status"] == "EVM_TRANSACTION_CONFIRMED"
    assert result["transaction_hash"] == tx_hash
    assert result["confirmations"] == 2
    assert not any(method == "eth_sendRawTransaction" for method, _ in calls)
    state = quote_oracle.json.loads(state_path.read_text(encoding="utf-8"))
    assert state["transactions"]["release"]["raw_transaction_hex"] == raw_hex


def test_signed_evm_recovery_rebroadcasts_only_the_exact_saved_bytes(tmp_path, monkeypatch):
    from eth_account import Account
    monkeypatch.setenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2")
    signer = Account.from_key("0x" + "00" * 31 + "01").address
    monkeypatch.setattr(Account, "recover_transaction", lambda _raw: signer)
    state_path, context, tx_hash, raw_hex = _signed_state_fixture(tmp_path)
    calls = []
    def fake_rpc(url, method, params):
        calls.append((method, params))
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getTransactionReceipt":
            receipt_calls = len([item for item in calls if item[0] == "eth_getTransactionReceipt"])
            if receipt_calls < 3:
                return None
            return {"status": "0x1", "blockNumber": "0xf"}
        if method == "eth_getTransactionByHash":
            return None
        if method == "eth_sendRawTransaction":
            assert params == [raw_hex]
            return tx_hash
        if method == "eth_blockNumber":
            return "0x10"
        raise AssertionError(method)
    monkeypatch.setattr(quote_oracle, "_rpc", fake_rpc)

    result = quote_oracle._recover_or_submit_signed_evm_transaction(
        "release", "0x1234", "0x" + "00" * 31 + "01",
        {"rpc_url": "https://evm.invalid", "chain_id": 1,
         "escrow_address": "0x00000000000000000000000000000000000000ee"},
        5, state_path, context,
    )

    assert result["status"] == "EVM_TRANSACTION_CONFIRMED"
    assert result["transaction_hash"] == tx_hash
    sent = [params for method, params in calls if method == "eth_sendRawTransaction"]
    assert sent == [[raw_hex]]
    assert not any(method == "eth_getTransactionCount" for method, _ in calls)
    assert not any(method == "eth_estimateGas" for method, _ in calls)
