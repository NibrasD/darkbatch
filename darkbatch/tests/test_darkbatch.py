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

def test_fba_exact_zatoshi_pro_rata_conservation():
    from darkbatch.engine.batch_solver import allocate_exact_pro_rata

    alice = create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_1)
    bob = create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_2)
    carol = create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_3)

    allocations = allocate_exact_pro_rata(2, [alice, bob, carol])
    assert sum(allocations.values()) == 2
    assert sorted(allocations.values()) == [0, 1, 1]
    assert allocate_exact_pro_rata(3, [alice, bob, carol]) == {
        alice.intent_id: 1, bob.intent_id: 1, carol.intent_id: 1
    }


def test_fba_clearing_never_rounds_marginal_fills_above_volume():
    buyers = [
        create_intent(OrderDirection.BUY_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_1),
        create_intent(OrderDirection.BUY_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_2),
    ]
    sellers = [
        create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_1),
        create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_2),
        create_intent(OrderDirection.SELL_ZEC, 0.00000001, 42.50, SAMPLE_SHIELDED_ADDR_3),
    ]
    result = BatchAuctionSolver().solve(11, buyers + sellers)
    buy_total = sum(fill.filled_zat for fill in result.buy_fills)
    sell_total = sum(fill.filled_zat for fill in result.sell_fills)
    assert round(result.total_cleared_zec * 100_000_000) == buy_total
    assert sell_total == buy_total
    assert buy_total == 2


def test_fba_clearing_price_tie_uses_an_observed_marginal_price():
    # At both $41 and $43, 15 ZEC can clear. Averaging tied candidates to $42
    # incorrectly makes both $45 and $43 buyers inframarginal and fills 20 ZEC.
    b1 = create_intent(OrderDirection.BUY_ZEC, 10.0, 45.0, SAMPLE_SHIELDED_ADDR_1)
    b2 = create_intent(OrderDirection.BUY_ZEC, 10.0, 43.0, SAMPLE_SHIELDED_ADDR_2)
    s1 = create_intent(OrderDirection.SELL_ZEC, 15.0, 41.0, SAMPLE_SHIELDED_ADDR_3)
    result = BatchAuctionSolver().solve(12, [b1, b2, s1])

    assert result.clearing_price_usd == 43.0
    assert sum(f.filled_zat for f in result.buy_fills) == 1_500_000_000
    assert sum(f.filled_zat for f in result.sell_fills) == 1_500_000_000
    assert next(f for f in result.buy_fills if f.intent_id == b1.intent_id).filled_zat == 1_000_000_000
    assert next(f for f in result.buy_fills if f.intent_id == b2.intent_id).filled_zat == 500_000_000


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
    Tests the legacy local-only bundle shape.
    These assertions do not prove authentic PCZT construction, spend validity, or note decryptability.
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

    # The built-in ShieldedWallet is a local mock, not an Orchard SpendingKey/FullViewingKey.
    # Do not claim this mock key can decrypt an authentic Zcash note. The bundle must be
    # treated as local-only until real key/address derivation and collaborative PCZT are implemented.
    assert bundle.live_broadcast_safe is False
    assert bundle.raw_tx_bytes_len == len(bytes.fromhex(bundle.raw_tx_hex))

def test_testnet_settlement_adapter_broadcast():
    """
    Verifies explicitly enabled local simulation stays labelled as simulation and returns no network txid.
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
    # Simulation must be explicitly enabled and can never look like a network tx.
    adapter = TestnetSettlementAdapter(node_simulator=node, rpc_url="", allow_simulation=True)

    receipt = adapter.broadcast(bundle)
    assert receipt["status"] == "SIMULATED_ONLY"
    assert receipt["network"] == "DarkBatch local simulator (not Zcash Testnet)"
    assert receipt["version_group_id"] == "0xd884b698"
    assert receipt["consensus_branch_id"] == "0x37a5165b"
    assert receipt["simulation_block_height"] >= 4134010
    assert receipt["confirmations"] == 0
    assert receipt["txid"] is None
    assert receipt["simulation_id"] == bundle.tx_id
    assert receipt["live_node"] is False
    assert receipt["simulation_only"] is True


def test_broadcast_raw_transaction_requires_v6_and_never_simulates(monkeypatch):
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

    adapter = TestnetSettlementAdapter(rpc_url="http://test-zebra", allow_simulation=False)
    monkeypatch.setattr(adapter, "is_live_rpc_available", lambda: True)
    calls = []

    def fake_rpc(method, params=None, timeout=3.0):
        calls.append((method, params))
        if method == "sendrawtransaction":
            return "ab" * 32
        raise AssertionError(f"Unexpected RPC method {method}")

    adapter._rpc_call = fake_rpc
    not_v6 = "02000000" + ("00" * 1200)
    with pytest.raises(ValueError, match="Transaction V6"):
        adapter.broadcast_raw_transaction(not_v6)
    assert calls == []

    v6_hex = "06000080" + ("00" * 1200)
    record = adapter.broadcast_raw_transaction(v6_hex)
    assert record["status"] == "BROADCAST_PENDING_CONFIRMATION"
    assert record["txid"] == "ab" * 32
    assert record["confirmations"] == 0
    assert record["epoch_settled"] is False
    assert record["simulation_only"] is False
    assert calls[0][0] == "sendrawtransaction"


def test_broadcast_raw_transaction_fails_when_testnet_rpc_is_unavailable():
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

    adapter = TestnetSettlementAdapter(rpc_url="", allow_simulation=False)
    with pytest.raises(RuntimeError, match="Activated Zebra Testnet RPC is unavailable"):
        adapter.broadcast_raw_transaction("06000080" + ("00" * 1200))
    assert adapter.broadcast_history == {}


def test_zebra_probe_uses_networkinfo_and_requires_activated_testnet():
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

    adapter = TestnetSettlementAdapter(rpc_url="http://fake-zebra", allow_simulation=False)
    calls = []

    def fake_rpc(method, params=None, timeout=3.0):
        calls.append(method)
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": 4_134_010}
        if method == "getnetworkinfo":
            return {"subversion": "/Zebra:1.0.0/"}
        raise AssertionError(f"Unexpected RPC method: {method}")

    adapter._rpc_call = fake_rpc
    assert adapter.is_live_rpc_available() is True
    assert calls == ["getblockchaininfo", "getnetworkinfo"]

    calls.clear()
    def non_zebra_rpc(method, params=None, timeout=3.0):
        calls.append(method)
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": 4_134_010}
        return {"subversion": "/zcashd:6.0.0/"}
    adapter._rpc_call = non_zebra_rpc
    assert adapter.is_live_rpc_available() is False


def test_testnet_adapter_fails_closed_without_rpc():
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter
    from darkbatch.node.simulator import ZcashNodeSimulator

    alice = ShieldedWallet("alice_fail_closed")
    bob = ShieldedWallet("bob_fail_closed")
    buyer = create_intent(OrderDirection.BUY_ZEC, 1.0, 45.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 1.0, 40.0, alice.unified_address)
    result = BatchAuctionSolver().solve(303, [buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result,
        {buyer.intent_id: buyer, seller.intent_id: seller},
        wallets_ivk_map={bob.unified_address: bob.ivk, alice.unified_address: alice.ivk},
    )

    node = ZcashNodeSimulator()
    start_height = node.height
    adapter = TestnetSettlementAdapter(node_simulator=node, rpc_url="", allow_simulation=False)

    with pytest.raises(RuntimeError, match="refusing to treat local simulation as settlement"):
        adapter.broadcast(bundle)

    # No local block is mined when production behavior has fail-closed enabled.
    assert node.height == start_height
    assert adapter.broadcast_history == {}
    assert bundle.live_broadcast_safe is False


def test_live_broadcast_refuses_uncertified_legacy_bundle(monkeypatch):
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

    alice = ShieldedWallet("alice_live_guard")
    bob = ShieldedWallet("bob_live_guard")
    buyer = create_intent(OrderDirection.BUY_ZEC, 1.0, 45.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 1.0, 40.0, alice.unified_address)
    result = BatchAuctionSolver().solve(304, [buyer, seller])
    bundle = SettlementBundleBuilder().build_bundle(
        result,
        {buyer.intent_id: buyer, seller.intent_id: seller},
        wallets_ivk_map={bob.unified_address: bob.ivk, alice.unified_address: alice.ivk},
    )

    adapter = TestnetSettlementAdapter(rpc_url="http://127.0.0.1:18232", allow_simulation=False)
    # Even if the RPC probe succeeds and a caller flips the bundle hint, the feature gate
    # must still refuse broadcast until real collaborative PCZT settlement is implemented.
    monkeypatch.setattr(adapter, "is_live_rpc_available", lambda: True)
    bundle.live_broadcast_safe = True

    with pytest.raises(RuntimeError, match="collaborative PCZT settlement is not implemented"):
        adapter.broadcast(bundle)

    assert adapter.broadcast_history == {}


def test_solver_api_path_does_not_mine_on_live_rpc_failure():
    from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter
    from darkbatch.node.simulator import ZcashNodeSimulator
    from darkbatch.solver.engine import AutonomousSolverDaemon

    alice = ShieldedWallet("alice_solver_guard")
    bob = ShieldedWallet("bob_solver_guard")
    buyer = create_intent(OrderDirection.BUY_ZEC, 1.0, 45.0, bob.unified_address)
    seller = create_intent(OrderDirection.SELL_ZEC, 1.0, 40.0, alice.unified_address)
    node = ZcashNodeSimulator()
    initial_height = node.height
    adapter = TestnetSettlementAdapter(node_simulator=node, rpc_url="", allow_simulation=False)
    solver = AutonomousSolverDaemon(node, settlement_adapter=adapter)

    result = solver.run_epoch_settlement(305, [buyer, seller], wallets_ivk_map={
        alice.unified_address: alice.ivk,
        bob.unified_address: bob.ivk,
    })

    assert result["status"] == "SETTLEMENT_BLOCKED"
    assert result["tx_id"] is None
    assert result["simulation_only"] is False
    assert node.height == initial_height
    assert solver.stats.total_settlement_txs_mined == 0

def test_nu6_3_consensus_and_crypto_integrity():
    """
    Checks local prototype constants and byte-shape invariants only.
    This test does not implement or verify Zcash consensus, authenticate a transaction,
    or test acceptance by Zebra. The node exercised below is only a simulator.
    """
    from darkbatch.core.crypto import encrypt_orchard_note, sign_redpallas_bundle, blake2b_digest
    from darkbatch.node.simulator import ZcashNodeSimulator

    # 1. Testnet Activation Height & Consensus Constants
    node = ZcashNodeSimulator()
    assert node.height >= 4134000
    info = node.get_blockchain_info()
    assert info["consensus"]["branch_id"] == "0x37a5165b"
    assert info["consensus"]["activation_height"] == 4134000
    assert "Local Simulator" in info["validator"]
    assert "not Zebra" in info["validator"]

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

    # 3. Check ciphertext byte lengths produced by the local prototype; this is not a consensus-validity test.
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

    # 4. Check non-empty signature-shaped outputs; these assertions do not cryptographically verify signatures.
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

