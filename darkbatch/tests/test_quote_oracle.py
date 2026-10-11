"""
Comprehensive Unit and Integration Tests for SettlementOracle
"""

import asyncio
import os
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from darkbatch.core.db import get_connection
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.settlement.quote_oracle import SettlementOracle


@pytest.fixture
def clean_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM settlement_attestations")
    cur.execute("DELETE FROM released_batches")
    conn.commit()
    conn.close()
    yield
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM settlement_attestations")
    cur.execute("DELETE FROM released_batches")
    conn.commit()
    conn.close()


@pytest.fixture
def oracle(clean_db):
    test_private_key = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    os.environ["TEST_ORACLE_KEY"] = test_private_key
    sim = ZcashNodeSimulator(initial_height=4134010)
    oracle_instance = SettlementOracle(
        zcash_rpc_url="http://127.0.0.1:18232",
        evm_rpc_url="http://127.0.0.1:8545",
        escrow_contract_address="0x1111111111111111111111111111111111111111",
        oracle_private_key_env_var="TEST_ORACLE_KEY",
        node_simulator=sim,
    )
    return oracle_instance


def test_oracle_init(oracle):
    assert oracle.oracle_address is not None
    assert oracle.oracle_address.startswith("0x")
    expected_address = Account.from_key(os.environ["TEST_ORACLE_KEY"]).address
    assert oracle.oracle_address == expected_address
    assert oracle.escrow_contract_address == "0x1111111111111111111111111111111111111111"


def test_create_attestation_and_signature_verification(oracle):
    async def run():
        batch_id = "batch-101"
        zcash_txid = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        clearing_price = 42.50
        total_zec = 100.0
        total_usd = 4250.0

        attestation = await oracle.create_settlement_attestation(
            batch_id=batch_id,
            zcash_txid=zcash_txid,
            clearing_price=clearing_price,
            total_zec=total_zec,
            total_usd=total_usd,
        )

        assert isinstance(attestation["attestation_hash"], bytes)
        assert len(attestation["attestation_hash"]) == 32
        assert isinstance(attestation["signature"], bytes)
        assert len(attestation["signature"]) == 65
        assert attestation["batch_id"] == batch_id
        assert attestation["zcash_txid"] == zcash_txid

        # Verify cryptographic signature using Account.recover_message
        signable_msg = encode_defunct(primitive=attestation["attestation_hash"])
        recovered_addr = Account.recover_message(signable_msg, signature=attestation["signature"])
        assert recovered_addr == oracle.oracle_address

        # Verify database persistence
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM settlement_attestations WHERE batch_id = ?", (batch_id,))
        row = cur.fetchone()
        conn.close()
        assert row is not None
        assert row["status"] == "ATTESTED"
        assert row["zcash_txid"] == zcash_txid

    asyncio.run(run())


def test_double_release_prevention(oracle):
    async def run():
        batch_id = "batch-202"
        zcash_txid = "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1"

        # Initially not released
        assert not await oracle.check_double_release(batch_id)

        attestation = await oracle.create_settlement_attestation(
            batch_id=batch_id,
            zcash_txid=zcash_txid,
            clearing_price=43.0,
            total_zec=50.0,
            total_usd=2150.0,
        )

        # First release should succeed
        evm_tx_hash = await oracle.submit_evm_release(attestation)
        assert evm_tx_hash.startswith("0x")
        assert len(evm_tx_hash) == 66

        # Now check_double_release must return True
        assert await oracle.check_double_release(batch_id)

        # Second release MUST raise ValueError to prevent double-release
        with pytest.raises(ValueError, match="Double-release prevented"):
            await oracle.submit_evm_release(attestation)

        # Also cannot refund an already released batch
        with pytest.raises(ValueError, match="Cannot refund"):
            await oracle.submit_evm_refund(batch_id, "settlement timeout")

    asyncio.run(run())


def test_evm_refund_submission(oracle):
    async def run():
        batch_id = "batch-303"
        zcash_txid = "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2"

        await oracle.create_settlement_attestation(
            batch_id=batch_id,
            zcash_txid=zcash_txid,
            clearing_price=41.0,
            total_zec=20.0,
            total_usd=820.0,
        )

        refund_tx = await oracle.submit_evm_refund(batch_id, "Miner fee timeout")
        assert refund_tx.startswith("0x")

        status = await oracle.get_settlement_status(batch_id)
        assert status["overall_status"] == "REFUNDED"
        assert status["evm_status"]["refunded"] is True

    asyncio.run(run())


def test_verify_zcash_tx_via_simulator(oracle):
    async def run():
        # Submit bundle into simulator to create a confirmed transaction
        tx_id = "d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3"
        bundle_dict = {
            "tx_id": tx_id,
            "epoch_id": 42,
            "action_groups": [],
        }
        success, block_hash = oracle.node_simulator.submit_settlement_bundle(bundle_dict)
        assert success

        # Verify with 1 confirmation
        res = await oracle.verify_zcash_tx(tx_id, expected_batch_id="42", min_confirmations=1)
        assert res["verified"] is True
        assert res["confirmations"] >= 1
        assert res["block_hash"] == block_hash

        # Verify with min_confirmations higher than actual
        res_high = await oracle.verify_zcash_tx(tx_id, expected_batch_id="42", min_confirmations=10)
        assert res_high["verified"] is False
        assert "Insufficient confirmations" in res_high["error"]

        # Verify mismatching batch
        res_mismatch = await oracle.verify_zcash_tx(tx_id, expected_batch_id="999", min_confirmations=1)
        assert res_mismatch["verified"] is False
        assert "Batch mismatch" in res_mismatch["error"]

        # Nonexistent transaction
        res_none = await oracle.verify_zcash_tx("nonexistent_txid", expected_batch_id="1")
        assert res_none["verified"] is False
        assert "not found" in res_none["error"]

    asyncio.run(run())


def test_price_feed_and_quote(oracle):
    async def run():
        price = await oracle.get_zec_usdc_price()
        assert price > 0.0

        quote = await oracle.get_quote(10.0)
        assert quote["pair"] == "ZEC/USDC"
        assert quote["zec_amount"] == 10.0
        assert quote["gross_usd"] > 0.0
        assert quote["net_usd"] < quote["gross_usd"]
        assert quote["solver_fee_usd"] > 0.0

    asyncio.run(run())
