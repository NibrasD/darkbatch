"""
Comprehensive Test Suite for DarkBatch
Tests cryptographic primitives, intent signing, FBA solver, MEV-neutrality, and v6 settlement.
"""

import json
import pytest
from darkbatch.core.crypto import (
    pedersen_commit,
    generate_scalar,
    encrypt_memo,
    decrypt_memo,
    aggregate_binding_keys,
    CURVE_ORDER,
)
from darkbatch.core.intent import create_intent, OrderDirection, SwapOrderIntent
from darkbatch.engine.batch_solver import BatchAuctionSolver
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder

SAMPLE_SHIELDED_ADDR_1 = "u1zcash99ironwoodsampleaddress001receivercomponent998877"
SAMPLE_SHIELDED_ADDR_2 = "u1zcash99ironwoodsampleaddress002receivercomponent112233"
SAMPLE_SHIELDED_ADDR_3 = "u1zcash99ironwoodsampleaddress003receivercomponent445566"
SHARED_KEY = b"DarkBatchMasterEncryptionKey32B!"

def test_pedersen_commitment():
    """Verifies that value commitments are deterministic for identical randomness."""
    r1 = generate_scalar()
    c1 = pedersen_commit(100_000_000, r1)
    c2 = pedersen_commit(100_000_000, r1)
    assert c1 == c2
    assert len(c1) == 64

    # Different randomness produces different commitments (hiding)
    r2 = generate_scalar()
    c3 = pedersen_commit(100_000_000, r2)
    assert c1 != c3

def test_512_byte_encrypted_memo():
    """Verifies round-trip encryption and padding of 512-byte Zcash shielded memo."""
    payload = json.dumps({"test": "settlement_receipt", "epoch": 42}).encode()
    encrypted = encrypt_memo(payload, SHARED_KEY)
    
    # Nonce (12) + Padded Memo (512) + Poly1305 Tag (16) = 540 bytes total
    assert len(encrypted) == 540
    
    decrypted = decrypt_memo(encrypted, SHARED_KEY)
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

def test_single_pair_batch_auction():
    """Tests an epoch with 1 buyer ($45) and 1 seller ($40)."""
    buyer = create_intent(
        direction=OrderDirection.BUY_ZEC,
        zec_amount=5.0,
        limit_price_usd=45.0,
        shielded_address=SAMPLE_SHIELDED_ADDR_1
    )
    seller = create_intent(
        direction=OrderDirection.SELL_ZEC,
        zec_amount=5.0,
        limit_price_usd=40.0,
        shielded_address=SAMPLE_SHIELDED_ADDR_2
    )

    solver = BatchAuctionSolver(solver_fee_bps=10)
    result = solver.solve(epoch_id=1, intents=[buyer, seller])

    assert result.total_cleared_zec == 5.0
    # Uniform price should be within [40, 45]
    assert 40.0 <= result.clearing_price_usd <= 45.0
    assert len(result.buy_fills) == 1
    assert len(result.sell_fills) == 1
    assert result.buy_fills[0].filled_zat == 500_000_000
    assert result.sell_fills[0].filled_zat == 500_000_000

def test_mev_resistance_and_order_invariance():
    """
    CRITICAL TEST: Proves that the batch auction is immune to front-running.
    Submitting orders in Order A vs Order B produces the exact same clearing price and volume.
    """
    b1 = create_intent(OrderDirection.BUY_ZEC, 10.0, 46.0, SAMPLE_SHIELDED_ADDR_1)
    b2 = create_intent(OrderDirection.BUY_ZEC, 5.0, 44.0, SAMPLE_SHIELDED_ADDR_2)
    s1 = create_intent(OrderDirection.SELL_ZEC, 8.0, 41.0, SAMPLE_SHIELDED_ADDR_3)
    s2 = create_intent(OrderDirection.SELL_ZEC, 7.0, 43.0, SAMPLE_SHIELDED_ADDR_1)

    solver = BatchAuctionSolver()

    # Sequence 1: Standard arrival
    seq1 = [b1, b2, s1, s2]
    res1 = solver.solve(epoch_id=10, intents=seq1)

    # Sequence 2: Arbitrary reordered / front-run arrival attempt
    seq2 = [s2, b2, s1, b1]
    res2 = solver.solve(epoch_id=10, intents=seq2)

    assert res1.clearing_price_usd == res2.clearing_price_usd
    assert res1.total_cleared_zec == res2.total_cleared_zec
    assert res1.total_cleared_usd == res2.total_cleared_usd

def test_v6_settlement_bundle_generation():
    """Tests building a complete ZIP 228 / v6 Ironwood settlement transaction bundle."""
    buyer = create_intent(OrderDirection.BUY_ZEC, 2.0, 44.0, SAMPLE_SHIELDED_ADDR_1)
    seller = create_intent(OrderDirection.SELL_ZEC, 2.0, 41.0, SAMPLE_SHIELDED_ADDR_2)
    intents_map = {buyer.intent_id: buyer, seller.intent_id: seller}

    solver = BatchAuctionSolver(solver_fee_bps=10)
    result = solver.solve(epoch_id=101, intents=[buyer, seller])

    builder = SettlementBundleBuilder()
    bundle = builder.build_bundle(result, intents_map, shared_symmetric_key=SHARED_KEY)

    assert bundle.tx_version == 6
    assert bundle.epoch_id == 101
    assert len(bundle.action_groups) == 2
    assert bundle.total_volume_zec == 2.0
    
    # Check that binding key is the sum of bsk_shares per ZIP 228
    expected_bsk = (buyer.bsk_share + seller.bsk_share) % CURVE_ORDER
    assert int(bundle.aggregated_binding_pubkey_hex, 16) == expected_bsk

    # Check encrypted memo in action description
    action_0 = bundle.action_groups[0].actions[0]
    raw_memo = bytes.fromhex(action_0.encrypted_memo_hex)
    decrypted_receipt = json.loads(decrypt_memo(raw_memo, SHARED_KEY))
    assert decrypted_receipt["protocol"] == "DarkBatch-Ironwood"
    assert decrypted_receipt["epoch"] == 101
    assert decrypted_receipt["filled_zec"] == 2.0
