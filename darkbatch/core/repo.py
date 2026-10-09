"""
DarkBatch Persistence Repository
Manages reads and writes to SQLite database ensuring consistent state across
CLI, API, and background Solver processes.
"""

import json
import time
from typing import Dict, List, Optional, Tuple, Any
from darkbatch.core.db import get_connection
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import SwapOrderIntent, OrderDirection

def seed_default_wallets_if_empty():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM wallets")
    count = cur.fetchone()[0]
    if count == 0:
        wallets = [
            ("alice", 150.0, 10000.0),
            ("bob", 80.0, 15000.0),
            ("whale", 1000.0, 100000.0),
            ("maker", 500.0, 50000.0),
        ]
        for alias, zec, usd in wallets:
            w = ShieldedWallet(alias)
            w.fund(zec, usd)
            cur.execute("""
            INSERT INTO wallets (alias, unified_address, seed_hex, ivk_hex, fvk_hex, balance_zat, balance_cents)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                w.alias, w.unified_address, w.seed.hex(), w.ivk.hex(),
                (w.ak + w.nk).hex(), w.shielded_balance_zat, w.quote_balance_cents
            ))
    conn.commit()
    conn.close()

seed_default_wallets_if_empty()

def list_wallets() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM wallets ORDER BY alias")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "alias": r["alias"],
            "unified_address": r["unified_address"],
            "ivk_hex": r["ivk_hex"][:24] + "...",
            "shielded_balance_zec": r["balance_zat"] / 100_000_000.0,
            "quote_balance_usd": r["balance_cents"] / 100.0
        } for r in rows
    ]

def get_wallet(alias: str) -> Optional[ShieldedWallet]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM wallets WHERE alias = ?", (alias,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    w = ShieldedWallet(r["alias"], seed=bytes.fromhex(r["seed_hex"]))
    w.shielded_balance_zat = r["balance_zat"]
    w.quote_balance_cents = r["balance_cents"]
    return w

def update_wallet_balance(unified_address: str, delta_zat: int, delta_cents: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    UPDATE wallets
    SET balance_zat = balance_zat + ?, balance_cents = balance_cents + ?
    WHERE unified_address = ?
    """, (delta_zat, delta_cents, unified_address))
    conn.commit()
    conn.close()

def save_intent(intent: SwapOrderIntent, epoch_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO intents (
        intent_id, direction, base_amount_zat, limit_price_cents,
        shielded_address, expiry_height, value_commitment, bsk_share,
        auth_pubkey_hex, signature_hex, epoch_id, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        intent.intent_id, intent.direction.value, intent.base_amount_zat,
        intent.limit_price_cents, intent.shielded_address, intent.expiry_height,
        intent.value_commitment, hex(intent.bsk_share), intent.auth_pubkey_hex,
        intent.signature_hex, epoch_id, "PENDING", intent.created_at_timestamp
    ))
    conn.commit()
    conn.close()

def get_pending_intents() -> List[SwapOrderIntent]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM intents WHERE status = 'PENDING'")
    rows = cur.fetchall()
    conn.close()
    res = []
    for r in rows:
        intent = SwapOrderIntent(
            intent_id=r["intent_id"],
            direction=OrderDirection(r["direction"]),
            base_amount_zat=r["base_amount_zat"],
            limit_price_cents=r["limit_price_cents"],
            shielded_address=r["shielded_address"],
            expiry_height=r["expiry_height"],
            created_at_timestamp=r["created_at"],
            blinding_scalar=1,  # deserialized
            value_commitment=r["value_commitment"],
            bsk_share=int(r["bsk_share"], 16),
            auth_pubkey_hex=r["auth_pubkey_hex"],
            signature_hex=r["signature_hex"]
        )
        res.append(intent)
    return res

def mark_intents_settled(intent_ids: List[str], status: str = "FILLED"):
    conn = get_connection()
    cur = conn.cursor()
    for i_id in intent_ids:
        cur.execute("UPDATE intents SET status = ? WHERE intent_id = ?", (status, i_id))
    conn.commit()
    conn.close()

def mark_intents_simulated(intent_ids: List[str]):
    """Close this demo batch without representing its intents as on-chain settled."""
    conn = get_connection()
    cur = conn.cursor()
    for i_id in intent_ids:
        cur.execute(
            "UPDATE intents SET status = 'SIMULATED_ONLY' WHERE intent_id = ? AND status = 'PENDING'",
            (i_id,)
        )
    conn.commit()
    conn.close()

def get_active_epoch_id() -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT MAX(epoch_id) FROM epochs")
    row = cur.fetchone()
    conn.close()
    if row and row[0] is not None:
        return row[0]
    return 1

def record_epoch_clear(
    epoch_id: int,
    clearing_price_usd: float,
    total_cleared_zec: float,
    total_cleared_usd: float,
    tx_id: Optional[str],
    block_hash: Optional[str]
):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO epochs (
        epoch_id, status, clearing_price_usd, total_cleared_zec,
        total_cleared_usd, tx_id, block_hash, created_at
    ) VALUES (?, 'CLEARED', ?, ?, ?, ?, ?, ?)
    """, (
        epoch_id, clearing_price_usd, total_cleared_zec,
        total_cleared_usd, tx_id, block_hash, time.time()
    ))
    # Open next epoch
    cur.execute("""
    INSERT OR IGNORE INTO epochs (epoch_id, status, created_at)
    VALUES (?, 'ACTIVE', ?)
    """, (epoch_id + 1, time.time()))
    conn.commit()
    conn.close()

def record_epoch_simulation(
    epoch_id: int,
    clearing_price_usd: float,
    total_cleared_zec: float,
    total_cleared_usd: float,
    simulation_id: str
):
    """Persist an FBA simulation without assigning a txid/block or claiming settlement."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO epochs (
        epoch_id, status, clearing_price_usd, total_cleared_zec,
        total_cleared_usd, tx_id, block_hash, created_at, simulation_id
    ) VALUES (?, 'SIMULATED', ?, ?, ?, NULL, NULL, ?, ?)
    """, (
        epoch_id, clearing_price_usd, total_cleared_zec,
        total_cleared_usd, time.time(), simulation_id
    ))
    cur.execute("""
    INSERT OR IGNORE INTO epochs (epoch_id, status, created_at)
    VALUES (?, 'ACTIVE', ?)
    """, (epoch_id + 1, time.time()))
    conn.commit()
    conn.close()

def get_epoch_history() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM epochs WHERE status IN ('CLEARED', 'SIMULATED') ORDER BY epoch_id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
