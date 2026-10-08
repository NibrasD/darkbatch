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

def test_zip228_action_groups_and_v6_bundle():
    """
    Tests building authentic ZIP 228 Action Groups containing [SwapAction, FeeAction]
    and Transaction v6 binary serialization.
    """
    alice = ShieldedWallet("alice")
    bob = ShieldedWallet("bob")

    buyer = create_intent(OrderDirection.BUY_ZEC, 5.0, 44.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 5.0, 41.0, alice.unified_address)
    intents_map = {buyer.intent_id: buyer, seller.intent_id: seller}
    ivk_map = {bob.unified_address: bob.ivk, alice.unified_address: alice.ivk}

    solver = BatchAuctionSolver()
    result = solver.solve(epoch_id=101, intents=[buyer, seller])

    builder = SettlementBundleBuilder()
    bundle = builder.build_bundle(result, intents_map, wallets_ivk_map=ivk_map)

    assert bundle.tx_version == 6
    assert bundle.version_group_id == 0x26a7270a
    assert bundle.consensus_branch_id == 0x2f8b66c3
    assert len(bundle.action_groups) == 2

    # Verify each Action Group contains BOTH a Swap Action and a Fee Action per ZIP 228!
    for ag in bundle.action_groups:
        assert ag.swap_action.action_type == "SWAP"
        assert ag.fee_action.action_type == "FEE"
        assert len(bytes.fromhex(ag.swap_action.encrypted_memo_hex)) == 512

    # Verify binary serialization
    assert len(bundle.raw_tx_hex) > 0
    assert bundle.raw_tx_bytes_len > 1000

    # Verify Bob can decrypt his confidential memo using his IVK
    bob_action = bundle.action_groups[0].swap_action
    bob_memo_bytes = bytes.fromhex(bob_action.encrypted_memo_hex)
    bob_shared_key = derive_shared_key(bob.ivk)
    decrypted_json = json.loads(decrypt_512_memo(bob_memo_bytes, bob_shared_key).decode("utf-8"))
    assert decrypted_json["protocol"] == "DarkBatch-ZIP228"
    assert decrypted_json["filled_zec"] == 5.0
