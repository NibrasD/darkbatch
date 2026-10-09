"""
DarkBatch tests: FBA matching, local demo helpers, and fail-closed Ironwood settlement.
These tests are not proof of consensus compliance or live Zebra acceptance.
"""

import json
import pytest

from darkbatch.core.crypto import (
    pedersen_commit,
    generate_scalar,
    encrypt_512_memo,
    decrypt_512_memo,
    aggregate_binding_keys,
    derive_shared_key,
)
from darkbatch.core.intent import create_intent, OrderDirection
from darkbatch.engine.batch_solver import BatchAuctionSolver
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter


SAMPLE_ADDRESS_1 = "u1-demo-alice-not-a-real-ironwood-address"
SAMPLE_ADDRESS_2 = "u1-demo-bob-not-a-real-ironwood-address"
SAMPLE_ADDRESS_3 = "u1-demo-maker-not-a-real-ironwood-address"


def test_pedersen_commitment_is_stable_for_same_inputs():
    randomness = generate_scalar()
    first = pedersen_commit(100_000_000, randomness)
    second = pedersen_commit(100_000_000, randomness)
    assert first == second
    assert len(first) == 64


def test_local_demo_receipt_envelope_roundtrip():
    wallet = ShieldedWallet("alice")
    key = derive_shared_key(wallet.ivk)
    payload = json.dumps({"kind": "demo_receipt", "epoch": 7}).encode()
    envelope = encrypt_512_memo(payload, key)
    assert len(envelope) == 512
    assert decrypt_512_memo(envelope, key) == payload


def test_intent_signature_roundtrip():
    intent = create_intent(
        OrderDirection.BUY_ZEC, 10.5, 42.0, SAMPLE_ADDRESS_1
    )
    assert intent.verify_signature()
    assert intent.base_amount_zat == 1_050_000_000
    assert intent.limit_price_cents == 4200


def test_fba_marginal_rationing():
    buyer_priority = create_intent(
        OrderDirection.BUY_ZEC, 10.0, 45.0, SAMPLE_ADDRESS_1
    )
    buyer_marginal = create_intent(
        OrderDirection.BUY_ZEC, 10.0, 42.5, SAMPLE_ADDRESS_2
    )
    seller = create_intent(
        OrderDirection.SELL_ZEC, 15.0, 42.5, SAMPLE_ADDRESS_3
    )
    result = BatchAuctionSolver().solve(
        1, [buyer_priority, buyer_marginal, seller]
    )
    assert result.total_cleared_zec == 15.0
    assert result.clearing_price_usd == 42.5
    priority_fill = next(
        fill for fill in result.buy_fills
        if fill.intent_id == buyer_priority.intent_id
    )
    marginal_fill = next(
        fill for fill in result.buy_fills
        if fill.intent_id == buyer_marginal.intent_id
    )
    assert priority_fill.filled_zat == 1_000_000_000
    assert marginal_fill.filled_zat == 500_000_000


def test_settlement_builder_returns_simulation_not_transaction():
    alice = ShieldedWallet("alice")
    bob = ShieldedWallet("bob")
    buyer = create_intent(OrderDirection.BUY_ZEC, 5.0, 44.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 5.0, 41.0, alice.unified_address)
    intents = {buyer.intent_id: buyer, seller.intent_id: seller}
    result = BatchAuctionSolver().solve(101, [buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result, intents,
        wallets_ivk_map={bob.unified_address: bob.ivk, alice.unified_address: alice.ivk},
    )
    assert bundle.tx_version == 6
    assert bundle.version_group_id == 0xD884B698
    assert bundle.consensus_branch_id == 0x37A5165B
    assert bundle.consensus_ready is False
    assert bundle.construction_mode == "LOCAL_SIMULATION_ONLY"
    assert bundle.tx_id is None
    assert bundle.raw_tx_hex == ""
    assert bundle.raw_tx_bytes_len == 0
    assert bundle.simulation_id.startswith("sim_")
    assert bundle.action_groups == []
    assert bundle.validation_blockers


def test_adapter_rejects_simulation_without_rpc_or_synthetic_mining():
    buyer = create_intent(OrderDirection.BUY_ZEC, 4.0, 45.0, SAMPLE_ADDRESS_2)
    seller = create_intent(OrderDirection.SELL_ZEC, 4.0, 40.0, SAMPLE_ADDRESS_1)
    result = BatchAuctionSolver().solve(202, [buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result, {buyer.intent_id: buyer, seller.intent_id: seller}
    )
    node = ZcashNodeSimulator()
    initial_height = node.height
    adapter = TestnetSettlementAdapter(node_simulator=node, rpc_url="")
    receipt = adapter.broadcast(bundle)
    assert receipt["status"] == "REJECTED_NOT_CONSENSUS_READY"
    assert receipt["broadcast"] is False
    assert receipt["confirmed"] is False
    assert receipt["tx_id"] is None
    assert node.height == initial_height
    assert len(node.blocks) == 1


def test_local_simulator_is_not_a_consensus_validator():
    node = ZcashNodeSimulator()
    initial_height = node.height
    initial_anchor = node.current_anchor()
    accepted, reason = node.submit_settlement_bundle({
        "tx_id": "not-a-real-transaction",
        "version_group_id": 0xD884B698,
        "consensus_branch_id": 0x37A5165B,
        "action_groups": [],
    })
    assert accepted is False
    assert "not a consensus validator" in reason
    assert node.height == initial_height
    assert len(node.blocks) == 1
    assert node.current_anchor() == initial_anchor
    info = node.get_blockchain_info()
    assert info["chain"] == "local-simulation"
    assert "NOT a consensus validator" in info["validator"]


def test_unverified_ironwood_crypto_helpers_fail_closed():
    from darkbatch.core import crypto

    with pytest.raises(RuntimeError, match="not been verified"):
        crypto.encrypt_orchard_note(
            lead_byte=0x03,
            diversifier=bytes(11),
            value_zat=500_000_000,
            rseed=bytes(32),
            memo_512=bytes(512),
            pk_d=bytes(32),
            ovk=bytes(32),
            cv=bytes(32),
            cmx=bytes(32),
        )
    with pytest.raises(RuntimeError, match="official Zcash transaction builder"):
        crypto.sign_redpallas_bundle(bytes(32), 1, 2)
    with pytest.raises(RuntimeError, match="Standalone output-only proofs"):
        crypto.generate_ironwood_proof(
            bytes(43), 100_000_000, bytes(512), bytes(32), bytes(32)
        )


def test_raw_broadcast_rejects_invalid_hex_without_rpc():
    adapter = TestnetSettlementAdapter(rpc_url="")
    receipt = adapter.broadcast_raw_transaction(
        raw_tx_hex="this-is-not-hex",
        expected_txid="11" * 32,
    )
    assert receipt["status"] == "REJECTED_INVALID_RAW_TX"
    assert receipt["broadcast"] is False
    assert receipt["confirmed"] is False
    assert receipt["confirmations"] == 0


def test_raw_broadcast_requires_real_testnet_rpc_after_header_checks():
    adapter = TestnetSettlementAdapter(rpc_url="")
    raw = (
        (0x80000006).to_bytes(4, "little")
        + (0xD884B698).to_bytes(4, "little")
        + (0x37A5165B).to_bytes(4, "little")
    )
    receipt = adapter.broadcast_raw_transaction(
        raw_tx_hex=raw.hex(),
        expected_txid="11" * 32,
    )
    assert receipt["status"] == "TESTNET_RPC_UNAVAILABLE"
    assert receipt["broadcast"] is False
    assert receipt["confirmed"] is False
    assert receipt["confirmations"] == 0


def test_official_builder_result_metadata_is_checked_before_use():
    from darkbatch.settlement.ironwood_transaction_client import _validate_result

    # Header-shape fixture only: this is intentionally NOT a valid transaction and
    # must never be sent to an RPC. It exercises the local client response validator.
    raw = (
        (0x80000006).to_bytes(4, "little")
        + (0xD884B698).to_bytes(4, "little")
        + (0x37A5165B).to_bytes(4, "little")
    )
    result = {
        "status": "BUILT_NOT_BROADCAST",
        "broadcast": False,
        "consensus_ready": True,
        "network": "testnet",
        "txid": "22" * 32,
        "raw_tx_hex": raw.hex(),
        "raw_tx_bytes_len": len(raw),
        "target_height": 4_134_000,
        "consensus_branch_id": "0x37a5165b",
        "transaction_version": 6,
        "version_group_id": "0xd884b698",
    }
    parsed = _validate_result(result)
    assert parsed.broadcast is False
    assert parsed.consensus_branch_id == 0x37A5165B
    assert parsed.raw_tx_bytes_len == 12

    bad = dict(result)
    bad["version_group_id"] = "0x00000001"
    with pytest.raises(RuntimeError, match="version-group ID"):
        _validate_result(bad)


def test_binding_share_aggregation_is_modular():
    from darkbatch.core.crypto import PALLAS_SCALAR_FIELD
    shares = [9, 13, PALLAS_SCALAR_FIELD - 4]
    assert aggregate_binding_keys(shares) == 18
