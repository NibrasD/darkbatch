"""
Comprehensive Test Suite for DarkBatch
Tests cryptographic primitives, strict 512-byte memos, FBA marginal rationing, and ZIP 228 v6 settlement.
"""

import json
import pytest
from darkbatch.core.crypto import (
    pedersen_commit,
    generate_scalar,
    encrypt_512_memo,
    decrypt_512_memo,
    encrypt_orchard_note,
    decrypt_orchard_note,
    aggregate_binding_keys,
    derive_shared_key,
    MEMO_TOTAL_SIZE,
    PALLAS_SCALAR_FIELD,
)
from darkbatch.core.intent import create_intent, OrderDirection, SwapOrderIntent
from darkbatch.engine.batch_solver import BatchAuctionSolver
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder
from darkbatch.core.wallet import ShieldedWallet

SAMPLE_SHIELDED_ADDR_1 = "u1zcash99ironwoodsampleaddress001receivercomponent998877"
SAMPLE_SHIELDED_ADDR_2 = "u1zcash99ironwoodsampleaddress002receivercomponent112233"
SAMPLE_SHIELDED_ADDR_3 = "u1zcash99ironwoodsampleaddress003receivercomponent445566"

def test_pedersen_commitment():
    """Verifies that value commitments on Pallas are deterministic for identical randomness."""
    r1 = generate_scalar()
    c1 = pedersen_commit(100_000_000, r1)
    c2 = pedersen_commit(100_000_000, r1)
    assert c1 == c2
    assert len(c1) == 64

def test_strictly_512_byte_encrypted_memo():
    """
    CRITICAL PROTOCOL TEST:
    Verifies that the encrypted memo buffer is STRICTLY 512 BYTES (ZIP 212 / ZIP 302).
    Not 540 bytes, not 513 bytes, EXACTLY 512 bytes.
    """
    alice_wallet = ShieldedWallet("alice")
    shared_key = derive_shared_key(alice_wallet.ivk)

    payload = json.dumps({"test": "settlement_receipt", "epoch": 42, "p_star": 42.60}).encode()
    encrypted_memo = encrypt_512_memo(payload, shared_key)
    
    assert len(encrypted_memo) == 512, "Zcash Shielded Memo MUST be strictly 512 bytes total!"
    
    decrypted = decrypt_512_memo(encrypted_memo, shared_key)
    assert decrypted == payload

def test_intent_creation_and_signature():
    """Verifies that off-chain SwapOrderIntent validates its signature correctly."""
    intent = create_intent(
        direction=OrderDirection.BUY_ZEC,
        zec_amount=10.5,
        limit_price_usd=42.0,
        shielded_address=SAMPLE_SHIELDED_ADDR_1
    )
    assert intent.verify_signature() is True
    assert intent.base_amount_zat == 1_050_000_000
    assert intent.limit_price_cents == 4200
    assert intent.quote_amount_usd == 10.5 * 42.0

def test_fba_inframarginal_priority_and_marginal_rationing():
    """
    MATHEMATICAL FBA TEST:
    Buyer 1 bids $45 (Inframarginal -> MUST be filled 100%)
    Buyer 2 bids $42.50 (Marginal -> gets remaining 5 ZEC = 50% pro-rata)
    Seller offers 15 ZEC at $40 (Cleared volume = 15 ZEC at P* = $42.50)
    """
    b1 = create_intent(OrderDirection.BUY_ZEC, 10.0, 45.0, SAMPLE_SHIELDED_ADDR_1)
    b2 = create_intent(OrderDirection.BUY_ZEC, 10.0, 42.50, SAMPLE_SHIELDED_ADDR_2)
    s1 = create_intent(OrderDirection.SELL_ZEC, 15.0, 42.50, SAMPLE_SHIELDED_ADDR_3)

    solver = BatchAuctionSolver()
    result = solver.solve(epoch_id=1, intents=[b1, b2, s1])

    assert result.total_cleared_zec == 15.0
    assert result.clearing_price_usd == 42.50
    
    # Check that Buyer 1 (Inframarginal) got 100% fill (10 ZEC)
    fill_b1 = next(f for f in result.buy_fills if f.intent_id == b1.intent_id)
    assert fill_b1.filled_zat == 1_000_000_000
    assert fill_b1.fill_percentage == 100.0
    assert fill_b1.is_marginal is False

    # Check that Buyer 2 (Marginal) got prorated fill (5 ZEC = 50%)
    fill_b2 = next(f for f in result.buy_fills if f.intent_id == b2.intent_id)
    assert fill_b2.filled_zat == 500_000_000
    assert fill_b2.fill_percentage == 50.0
    assert fill_b2.is_marginal is True

def test_mev_resistance_and_order_invariance():
    """
    Verifies that the batch auction is immune to front-running.
    Submitting orders in Sequence A vs Sequence B produces the exact same clearing price and volume.
    """
    b1 = create_intent(OrderDirection.BUY_ZEC, 10.0, 46.0, SAMPLE_SHIELDED_ADDR_1)
    b2 = create_intent(OrderDirection.BUY_ZEC, 5.0, 44.0, SAMPLE_SHIELDED_ADDR_2)
    s1 = create_intent(OrderDirection.SELL_ZEC, 8.0, 41.0, SAMPLE_SHIELDED_ADDR_3)
    s2 = create_intent(OrderDirection.SELL_ZEC, 7.0, 43.0, SAMPLE_SHIELDED_ADDR_1)

    solver = BatchAuctionSolver()

    seq1 = [b1, b2, s1, s2]
    res1 = solver.solve(epoch_id=10, intents=seq1)

    seq2 = [s2, b2, s1, b1]
    res2 = solver.solve(epoch_id=10, intents=seq2)

    assert res1.clearing_price_usd == res2.clearing_price_usd
    assert res1.total_cleared_zec == res2.total_cleared_zec
    assert res1.total_cleared_usd == res2.total_cleared_usd

def test_bundle_builder_fails_closed_without_wallet_authorized_ironwood_inputs():
    """An off-chain intent is not a spend authorization or a consensus transaction."""
    alice = ShieldedWallet("alice")
    bob = ShieldedWallet("bob")
    buyer = create_intent(OrderDirection.BUY_ZEC, 5.0, 44.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 5.0, 41.0, alice.unified_address)
    intents_map = {buyer.intent_id: buyer, seller.intent_id: seller}
    result = BatchAuctionSolver().solve(epoch_id=101, intents=[buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result, intents_map, wallets_ivk_map={bob.unified_address: bob.ivk, alice.unified_address: alice.ivk}
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

def test_testnet_adapter_rejects_simulation_without_broadcast():
    """A simulation must not be accepted by a fake local consensus path or live RPC."""
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter
    from darkbatch.node.simulator import ZcashNodeSimulator

    buyer = create_intent(OrderDirection.BUY_ZEC, 4.0, 45.0, SAMPLE_SHIELDED_ADDR_2)
    seller = create_intent(OrderDirection.SELL_ZEC, 4.0, 40.0, SAMPLE_SHIELDED_ADDR_1)
    result = BatchAuctionSolver().solve(epoch_id=202, intents=[buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result, {buyer.intent_id: buyer, seller.intent_id: seller}
    )
    node = ZcashNodeSimulator()
    initial_height = node.height
    adapter = TestnetSettlementAdapter(node_simulator=node)

    receipt = adapter.broadcast(bundle)
    assert receipt["status"] == "REJECTED_NOT_CONSENSUS_READY"
    assert receipt["broadcast"] is False
    assert receipt["confirmed"] is False
    assert receipt["tx_id"] is None
    assert node.height == initial_height
    assert len(node.blocks) == 1

def test_local_simulator_never_mines_or_claims_consensus():
    from darkbatch.node.simulator import ZcashNodeSimulator

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

def test_nu6_3_consensus_and_crypto_integrity():
    """
    Checks target constants and primitive output shapes only. This test does not
    establish Ironwood consensus compliance or Zebra transaction acceptance.
    """
    from darkbatch.core.crypto import encrypt_orchard_note, sign_redpallas_bundle, blake2b_digest
    from darkbatch.node.simulator import ZcashNodeSimulator

    # 1. Testnet Activation Height & Consensus Constants
    node = ZcashNodeSimulator()
    assert node.height >= 4134000
    info = node.get_blockchain_info()
    assert info["consensus"]["branch_id"] == "0x37a5165b"
    assert info["consensus"]["activation_height"] == 4134000
    assert "NOT a consensus validator" in info["validator"]

    # 2. Reject invalid target branch metadata (the simulator does not validate consensus)
    invalid_bundle = {
        "tx_id": "test_invalid_branch",
        "version_group_id": 0xD884B698,
        "consensus_branch_id": 0x2f8b66c3,  # Old/incorrect branch ID
        "action_groups": []
    }
    ok, err = node.submit_settlement_bundle(invalid_bundle)
    assert ok is False
    assert "0x37A5165B" in err

    # 3. Check expected ciphertext lengths from the Rust primitive; not a consensus test.
    enc_ct, out_ct, epk = encrypt_orchard_note(
        lead_byte=0x03,
        diversifier=bytes(11),
        value_zat=500_000_000,
        rseed=bytes(32),
        memo_512=bytes(512),
        pk_d=bytes(32),
        ovk=bytes(32),
        cv=bytes(32),
        cmx=bytes(32)
    )
    assert len(enc_ct) == 580
    assert len(out_ct) == 80
    assert len(epk) == 32
    assert enc_ct != bytes(580)

    # 4. Check signature byte lengths only; no bundle-level authorization is proved here.
    sighash = blake2b_digest(b"canonical_sighash_data", personalization=b"ZcashTxHashIronw")
    bsk = 12345678901234567890
    spend_sigs, rk_list, binding_sig = sign_redpallas_bundle(sighash, bsk, 2)
    assert len(spend_sigs) == 2
    assert len(rk_list) == 2
    for s in spend_sigs:
        assert len(s) == 64
        assert s != bytes(64)  # STRICTLY non-zero
    for r in rk_list:
        assert len(r) == 32
        assert r != bytes(32)  # STRICTLY non-zero
    assert len(binding_sig) == 64
    assert binding_sig != bytes(64)  # STRICTLY non-zero

