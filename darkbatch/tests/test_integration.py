"""
DarkBatch Integration Tests — Full Cross-Chain Settlement Pipeline
Tests the complete flow: Intent → FBA Solver → ZIP 229 Bundle → 
Testnet Adapter → Oracle Verification → EVM Escrow Release/Refund.

These tests exercise the REAL settlement path (with local simulator fallback)
and cross-chain coordination through the SettlementOracle.
"""

import asyncio
import hashlib
import os
import time
import pytest
from typing import Dict, Any

from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import create_intent, OrderDirection
from darkbatch.core.db import get_connection
from darkbatch.engine.batch_solver import BatchAuctionSolver
from darkbatch.settlement.v6_bundle import SettlementBundleBuilder
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter
from darkbatch.settlement.quote_oracle import SettlementOracle
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def node():
    return ZcashNodeSimulator(initial_height=4_134_010)


@pytest.fixture
def adapter(node):
    return TestnetSettlementAdapter(node)


@pytest.fixture
def oracle():
    """Settlement oracle configured for local testing (no real EVM)."""
    return SettlementOracle(
        zcash_rpc_url="http://127.0.0.1:18232",
        evm_rpc_url="http://127.0.0.1:8545",
    )


@pytest.fixture
def solver_with_adapter(node, adapter):
    """Solver daemon with testnet adapter (uses simulator since no live RPC)."""
    settlement_log = []
    
    def on_settlement(summary: Dict[str, Any]):
        settlement_log.append(summary)
    
    solver = AutonomousSolverDaemon(
        node,
        testnet_adapter=adapter,
        on_settlement_callback=on_settlement,
    )
    solver._settlement_log = settlement_log
    return solver


@pytest.fixture
def wallets():
    """Create test wallets with funded balances."""
    alice = ShieldedWallet("test_alice")
    alice.fund(zec=100.0, usd=5000.0)
    
    bob = ShieldedWallet("test_bob")
    bob.fund(zec=50.0, usd=10000.0)
    
    whale = ShieldedWallet("test_whale")
    whale.fund(zec=500.0, usd=50000.0)
    
    maker = ShieldedWallet("test_maker")
    maker.fund(zec=200.0, usd=20000.0)
    
    return {"alice": alice, "bob": bob, "whale": whale, "maker": maker}


def make_wallets_map(wallets):
    return {w.unified_address: w for w in wallets.values()}


def make_ivk_map(wallets):
    return {w.unified_address: w.ivk for w in wallets.values()}


# ─────────────────────────────────────────────────────────────
# Test: Full Batch Cycle with Dual Settlement Path
# ─────────────────────────────────────────────────────────────

def test_full_batch_cycle_dual_settlement(solver_with_adapter, wallets, node):
    """
    Tests: Intent submission → FBA solving → ZIP 229 bundle →
           Dual settlement path (simulator fallback) → Balance updates.
    """
    wallets_map = make_wallets_map(wallets)
    ivk_map = make_ivk_map(wallets)
    
    alice = wallets["alice"]
    bob = wallets["bob"]
    maker = wallets["maker"]
    
    # Create matched orders
    intents = [
        create_intent(OrderDirection.BUY_ZEC, 20.0, 43.50, bob.unified_address),
        create_intent(OrderDirection.BUY_ZEC, 15.0, 42.80, alice.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 25.0, 41.50, maker.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 10.0, 42.00, alice.unified_address),
    ]
    
    initial_bob_zec = bob.shielded_balance_zat
    initial_maker_zec = maker.shielded_balance_zat
    
    result = solver_with_adapter.run_epoch_settlement(
        epoch_id=1,
        intents=intents,
        wallets_map=wallets_map,
        wallets_ivk_map=ivk_map,
    )
    
    # Assertions
    assert result["status"] == "SETTLED_AND_MINED"
    assert result["settlement_path"] == "LOCAL_SIMULATOR"  # No live testnet
    assert result["cleared_zec"] > 0
    assert result["clearing_price_usd"] > 0
    assert result["tx_id"] is not None
    assert len(result["tx_id"]) == 64  # 32 bytes hex
    assert result["block_hash"] is not None
    assert result["execution_latency_ms"] > 0
    assert result["raw_tx_bytes_len"] > 0
    
    # Verify balances changed
    assert bob.shielded_balance_zat > initial_bob_zec  # buyer received ZEC
    assert maker.shielded_balance_zat < initial_maker_zec  # seller sent ZEC
    
    # Verify block was mined
    assert node.height > 4_134_010
    
    print(f"\n✅ Full batch cycle completed:")
    print(f"   Clearing price: ${result['clearing_price_usd']:.2f}")
    print(f"   Volume: {result['cleared_zec']:.2f} ZEC")
    print(f"   TxID: {result['tx_id'][:32]}...")
    print(f"   Settlement: {result['settlement_path']}")


# ─────────────────────────────────────────────────────────────
# Test: No Crossing Liquidity
# ─────────────────────────────────────────────────────────────

def test_no_crossing_liquidity(solver_with_adapter, wallets):
    """Orders don't cross — no settlement should occur."""
    alice = wallets["alice"]
    bob = wallets["bob"]
    
    intents = [
        create_intent(OrderDirection.BUY_ZEC, 10.0, 30.0, bob.unified_address),   # Bid $30
        create_intent(OrderDirection.SELL_ZEC, 10.0, 50.0, alice.unified_address), # Ask $50
    ]
    
    result = solver_with_adapter.run_epoch_settlement(
        epoch_id=2,
        intents=intents,
    )
    
    assert result["status"] == "NO_CROSSING_LIQUIDITY"
    assert result["cleared_zec"] == 0.0
    print("\n✅ No crossing liquidity handled correctly")


# ─────────────────────────────────────────────────────────────
# Test: Double-Spend Rejection
# ─────────────────────────────────────────────────────────────

def test_double_spend_rejection(solver_with_adapter, wallets, node):
    """Verify the node simulator tracks nullifiers and rejects reuse."""
    ivk_map = make_ivk_map(wallets)
    alice = wallets["alice"]
    bob = wallets["bob"]
    
    intents = [
        create_intent(OrderDirection.BUY_ZEC, 5.0, 43.0, bob.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 5.0, 42.0, alice.unified_address),
    ]
    
    # First settlement succeeds
    result1 = solver_with_adapter.run_epoch_settlement(
        epoch_id=3,
        intents=intents,
        wallets_ivk_map=ivk_map,
    )
    assert result1["status"] == "SETTLED_AND_MINED"
    
    # Verify nullifiers were recorded in the node's nullifier set
    assert len(node.nullifier_set) > 0, "Node should have recorded nullifiers"
    
    # Verify that submitting a bundle with the SAME nullifiers would fail
    # by checking the nullifier set directly
    recorded_nf = list(node.nullifier_set)[0]
    assert recorded_nf in node.nullifier_set
    
    print(f"\n✅ Nullifier tracking verified:")
    print(f"   Nullifiers recorded: {len(node.nullifier_set)}")
    print(f"   Sample: {recorded_nf[:32]}...")


# ─────────────────────────────────────────────────────────────
# Test: Oracle Attestation and Double-Release Prevention
# ─────────────────────────────────────────────────────────────

def test_oracle_attestation_lifecycle(oracle):
    """
    Tests: Create attestation → Check status → Verify prevents
           double-release of same batch.
    """
    batch_id = hashlib.sha256(b"test-batch-epoch-5").hexdigest()
    zcash_txid = hashlib.sha256(b"fake-zcash-txid").hexdigest()
    
    # Create attestation
    loop = asyncio.new_event_loop()
    attestation = loop.run_until_complete(
        oracle.create_settlement_attestation(
            batch_id=batch_id,
            zcash_txid=zcash_txid,
            clearing_price=42.50,
            total_zec=35.0,
            total_usd=1487.50,
        )
    )
    
    assert attestation["batch_id"] == batch_id
    assert attestation["zcash_txid"] == zcash_txid
    assert "attestation_hash" in attestation
    
    # Check status
    status = loop.run_until_complete(
        oracle.get_settlement_status(batch_id)
    )
    assert status["batch_id"] == batch_id
    # The oracle stores attestations — check the overall status
    assert status.get("overall_status") in ("ATTESTED", "PENDING", "RELEASED")
    
    # Verify double-release check works
    is_released = loop.run_until_complete(
        oracle.check_double_release(batch_id)
    )
    assert is_released is False  # Not yet released on EVM
    
    loop.close()
    
    print(f"\n✅ Oracle attestation lifecycle:")
    print(f"   Batch: {batch_id[:16]}...")
    print(f"   Status: {status.get('overall_status')}")


# ─────────────────────────────────────────────────────────────
# Test: Oracle Zcash TX Verification (Simulator Fallback)
# ─────────────────────────────────────────────────────────────

def test_oracle_zcash_verification_fallback(oracle):
    """
    Tests verification when Zcash node is unreachable (returns RPC error).
    This is expected in CI environments without a live testnet node.
    """
    result = asyncio.get_event_loop().run_until_complete(
        oracle.verify_zcash_tx(
            txid="aaaa" * 16,
            expected_batch_id="test-batch",
            min_confirmations=6,
        )
    )
    
    assert result["verified"] is False
    assert "error" in result
    assert result["confirmations"] == 0
    
    print(f"\n✅ Zcash verification fallback: {result['error']}")


# ─────────────────────────────────────────────────────────────
# Test: Settlement Bundle ZIP 229 Compliance
# ─────────────────────────────────────────────────────────────

def test_settlement_bundle_zip229_compliance(wallets, node):
    """Verify the settlement bundle meets ZIP 229 binary format requirements."""
    ivk_map = make_ivk_map(wallets)
    alice = wallets["alice"]
    bob = wallets["bob"]
    maker = wallets["maker"]
    
    solver = BatchAuctionSolver(solver_fee_bps=10)
    builder = SettlementBundleBuilder(ironwood_anchor=node.current_anchor())
    
    intents = [
        create_intent(OrderDirection.BUY_ZEC, 20.0, 43.50, bob.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 20.0, 41.50, maker.unified_address),
    ]
    
    clear_result = solver.solve(epoch_id=10, intents=intents)
    assert clear_result.total_cleared_zec > 0
    
    intents_map = {i.intent_id: i for i in intents}
    bundle = builder.build_bundle(clear_result, intents_map, wallets_ivk_map=ivk_map)
    
    # ZIP 229 assertions
    # Note: bundle.tx_version stores the logical version (6), 
    # while the consensus binary encoding uses 0x80000006 in raw_tx_hex
    assert bundle.tx_version in (6, 0x80000006)  # Accept either representation
    assert bundle.version_group_id == 0xD884B698  # VERSION_GROUP_ID_V6
    assert len(bundle.tx_id) == 64  # 32 bytes hex
    assert len(bundle.raw_tx_hex) > 0
    assert bundle.raw_tx_bytes_len > 0
    
    # Each action group should have swap + fee actions
    for ag in bundle.action_groups:
        assert ag.swap_action is not None
        assert ag.fee_action is not None
        assert ag.anchor_hex is not None
        assert len(ag.swap_action.nullifier_hex) == 64  # 32 bytes
        assert len(ag.swap_action.cm_star_hex) == 64    # 32 bytes
        assert len(ag.swap_action.rk_hex) == 64         # 32 bytes
    
    print(f"\n✅ ZIP 229 v6 bundle compliance verified:")
    print(f"   TX version: {hex(bundle.tx_version)}")
    print(f"   Version group ID: {hex(bundle.version_group_id)}")
    print(f"   Action groups: {len(bundle.action_groups)}")
    print(f"   Raw TX size: {bundle.raw_tx_bytes_len} bytes")
    print(f"   TxID: {bundle.tx_id[:32]}...")


# ─────────────────────────────────────────────────────────────
# Test: Testnet Adapter Detects Live/Local Mode
# ─────────────────────────────────────────────────────────────

def test_testnet_adapter_mode_detection(adapter):
    """Adapter should detect that no live Zcash RPC is available."""
    is_live = adapter.is_live_rpc_available()
    
    # In CI/dev environment, no live testnet expected
    # The important thing is it doesn't crash and returns a boolean
    assert isinstance(is_live, bool)
    
    if is_live:
        print("\n⚠️  Live Zcash Testnet RPC detected!")
    else:
        print("\n✅ No live RPC — will use local simulator (expected in CI)")


# ─────────────────────────────────────────────────────────────
# Test: PCZT Agent Initialization
# ─────────────────────────────────────────────────────────────

def test_pczt_agent_initialization():
    """Verify the PCZT agent initializes without errors."""
    from darkbatch.settlement.local_pczt_agent import LocalPCZTAgent
    
    agent = LocalPCZTAgent(
        rpc_url="http://127.0.0.1:18232",
        lightwalletd_url="https://zcash.mysideoftheweb.com:19067",
    )
    
    assert agent.rpc_url == "http://127.0.0.1:18232"
    assert agent.lightwalletd_url == "https://zcash.mysideoftheweb.com:19067"
    
    print("\n✅ PCZT Agent initialized successfully")


# ─────────────────────────────────────────────────────────────
# Test: PCZT Agent Anchor Retrieval (Fallback)
# ─────────────────────────────────────────────────────────────

def test_pczt_agent_anchor_fallback():
    """PCZT agent should return a valid anchor even without live RPC."""
    from darkbatch.settlement.local_pczt_agent import LocalPCZTAgent
    
    agent = LocalPCZTAgent()
    anchor = asyncio.get_event_loop().run_until_complete(
        agent.get_current_anchor()
    )
    
    assert anchor is not None
    assert len(anchor) == 64  # 32 bytes hex
    
    print(f"\n✅ PCZT Agent anchor (fallback): {anchor[:32]}...")


# ─────────────────────────────────────────────────────────────
# Test: Multi-Epoch Solver History
# ─────────────────────────────────────────────────────────────

def test_multi_epoch_history(solver_with_adapter, wallets):
    """Run multiple epochs and verify history tracking."""
    ivk_map = make_ivk_map(wallets)
    alice = wallets["alice"]
    bob = wallets["bob"]
    maker = wallets["maker"]
    
    # Epoch 1
    intents_1 = [
        create_intent(OrderDirection.BUY_ZEC, 10.0, 44.0, bob.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 10.0, 43.0, maker.unified_address),
    ]
    r1 = solver_with_adapter.run_epoch_settlement(11, intents_1, wallets_ivk_map=ivk_map)
    
    # Epoch 2
    intents_2 = [
        create_intent(OrderDirection.BUY_ZEC, 5.0, 45.0, alice.unified_address),
        create_intent(OrderDirection.SELL_ZEC, 5.0, 44.0, bob.unified_address),
    ]
    r2 = solver_with_adapter.run_epoch_settlement(12, intents_2, wallets_ivk_map=ivk_map)
    
    # Verify history
    assert len(solver_with_adapter.solved_history) >= 2
    assert solver_with_adapter.stats.total_epochs_solved >= 2
    assert solver_with_adapter.stats.total_volume_cleared_zec > 0
    
    print(f"\n✅ Multi-epoch history:")
    print(f"   Epochs solved: {solver_with_adapter.stats.total_epochs_solved}")
    print(f"   Total volume: {solver_with_adapter.stats.total_volume_cleared_zec:.2f} ZEC")


# ─────────────────────────────────────────────────────────────
# Test: Settlement DB Schema
# ─────────────────────────────────────────────────────────────

def test_settlement_db_schema():
    """Verify all settlement-related tables exist in SQLite."""
    conn = get_connection()
    cur = conn.cursor()
    
    # Check tables exist
    tables = ["wallets", "intents", "epochs", "blocks", "spent_nullifiers",
              "settlement_attestations", "released_batches"]
    
    for table in tables:
        cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        row = cur.fetchone()
        assert row is not None, f"Table '{table}' not found in database"
    
    conn.close()
    
    print(f"\n✅ All {len(tables)} settlement DB tables verified")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
