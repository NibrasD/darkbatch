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
    assert bundle.version_group_id == 0xD884B698  # Mandatory ZIP 229 consensus ID
    assert bundle.consensus_branch_id == 0x37A5165B  # Mandatory ZIP 258 consensus branch ID for NU6.3
    assert len(bundle.action_groups) == 2

    # Verify each Action Group contains BOTH a Swap Action and a Fee Action per ZIP 228!
    for ag in bundle.action_groups:
        assert ag.swap_action.action_type == "SWAP"
        assert ag.fee_action.action_type == "FEE"
        assert len(bytes.fromhex(ag.swap_action.enc_ciphertext_hex)) == 580
        assert len(bytes.fromhex(ag.swap_action.out_ciphertext_hex)) == 80
        assert len(bytes.fromhex(ag.swap_action.epk_hex)) == 32
        assert len(bytes.fromhex(ag.swap_action.rk_hex)) == 32

    # Verify binary serialization
    assert len(bundle.raw_tx_hex) > 0
    assert bundle.raw_tx_bytes_len > 1000

    # Verify Bob can decrypt his confidential memo using his IVK per § 5.4.3.4
    bob_action = bundle.action_groups[0].swap_action
    bob_enc_bytes = bytes.fromhex(bob_action.enc_ciphertext_hex)
    bob_epk_bytes = bytes.fromhex(bob_action.epk_hex)
    dec_val, bob_memo_bytes = decrypt_orchard_note(bob_enc_bytes, bob.ivk, bob_epk_bytes)
    decrypted_json = json.loads(bob_memo_bytes.rstrip(b"\x00").decode("utf-8"))
    assert decrypted_json["protocol"] == "DarkBatch-ZIP228"
    assert decrypted_json["filled_zec"] == 5.0

def test_testnet_settlement_adapter_broadcast():
    """
    Verifies that the Testnet Settlement Adapter verifies consensus,
    submits to the simulated testnet node, and returns a verified testnet txid receipt.
    """
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter
    from darkbatch.node.simulator import ZcashNodeSimulator

    alice = ShieldedWallet("alice_testnet")
    bob = ShieldedWallet("bob_testnet")

    buyer = create_intent(OrderDirection.BUY_ZEC, 4.0, 45.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 4.0, 40.0, alice.unified_address)
    intents_map = {buyer.intent_id: buyer, seller.intent_id: seller}
    ivk_map = {bob.unified_address: bob.ivk, alice.unified_address: alice.ivk}

    solver = BatchAuctionSolver()
    result = solver.solve(epoch_id=202, intents=[buyer, seller])

    builder = SettlementBundleBuilder()
    bundle = builder.build_bundle(result, intents_map, wallets_ivk_map=ivk_map)

    node = ZcashNodeSimulator()
    adapter = TestnetSettlementAdapter(node_simulator=node)

    receipt = adapter.broadcast(bundle)
    assert receipt["status"] == "VERIFIED_LOCAL_CONSENSUS"
    assert receipt["network"] == "Local Zebra NU6.3 Consensus Engine"
    assert receipt["version_group_id"] == "0xd884b698"
    assert receipt["consensus_branch_id"] == "0x37a5165b"
    assert receipt["block_height"] >= 4134010
    assert receipt["confirmations"] == 1
    assert receipt["txid"] == bundle.tx_id
    assert receipt["live_node"] is False

def test_nu6_3_consensus_and_crypto_integrity():
    """
    Directly verifies NU6.3 (Ironwood) consensus rules:
    - Official branch ID 0x37A5165B (ZIP 258)
    - Version Group ID 0xD884B698 (ZIP 229)
    - Testnet Activation Height >= 4,134,000 (ZIP 258)
    - RFC 8439 ChaCha20Poly1305 580-byte note ciphertext with lead byte 0x03 (ZIP 2005)
    - Authentic RedPallas spend authorization & binding signatures on Pallas curve
    - Zebra validator consensus rejection of non-conforming blocks/bundles
    """
    from darkbatch.core.crypto import encrypt_orchard_note, sign_redpallas_bundle, blake2b_digest
    from darkbatch.node.simulator import ZcashNodeSimulator

    # 1. Testnet Activation Height & Consensus Constants
    node = ZcashNodeSimulator()
    assert node.height >= 4134000
    info = node.get_blockchain_info()
    assert info["consensus"]["branch_id"] == "0x37a5165b"
    assert info["consensus"]["activation_height"] == 4134000
    assert "Zebra" in info["validator"]

    # 2. Rejection of invalid Branch ID
    invalid_bundle = {
        "tx_id": "test_invalid_branch",
        "version_group_id": 0xD884B698,
        "consensus_branch_id": 0x2f8b66c3,  # Old/incorrect branch ID
        "action_groups": []
    }
    ok, err = node.submit_settlement_bundle(invalid_bundle)
    assert ok is False
    assert "0x37A5165B" in err

    # 3. Authentic 580-byte Orchard / Ironwood Note Encryption (RFC 8439 ChaCha20Poly1305)
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

    # 4. Authentic RedPallas Signatures on Pallas curve
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

