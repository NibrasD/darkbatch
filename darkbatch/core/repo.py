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
        shielded_address, quote_address, expiry_height, value_commitment, bsk_share,
        auth_pubkey_hex, signature_hex, epoch_id, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        intent.intent_id, intent.direction.value, intent.base_amount_zat,
        intent.limit_price_cents, intent.shielded_address, intent.quote_address, intent.expiry_height,
        intent.value_commitment, hex(intent.bsk_share), intent.auth_pubkey_hex,
        intent.signature_hex, epoch_id, "PENDING", intent.created_at_timestamp
    ))
    conn.commit()
    conn.close()

def get_pending_intents(epoch_id: Optional[int] = None) -> List[SwapOrderIntent]:
    conn = get_connection()
    cur = conn.cursor()
    if epoch_id is None:
        cur.execute("SELECT * FROM intents WHERE status = 'PENDING' ORDER BY intent_id")
    else:
        cur.execute(
            "SELECT * FROM intents WHERE status = 'PENDING' AND epoch_id = ? ORDER BY intent_id",
            (epoch_id,),
        )
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
            quote_address=r["quote_address"] if "quote_address" in r.keys() else None,
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
    INSERT INTO epochs (epoch_id, status, created_at)
    VALUES (?, 'ACTIVE', ?)
    """, (epoch_id + 1, time.time()))
    conn.commit()
    conn.close()

def record_epoch_zec_pending(
    epoch_id: int,
    clearing_price_usd: float,
    total_cleared_zec: float,
    total_cleared_usd: float,
    tx_id: str,
    intent_ids: List[str],
    quote_batch_id: Optional[str] = None,
    quote_plan_hash: Optional[str] = None,
    quote_total_micro: Optional[int] = None,
    quote_escrow_data_hash: Optional[str] = None,
    quote_chain_id: Optional[int] = None,
    target_height: Optional[int] = None,
    consensus_branch_id: Optional[str] = None,
):
    """Persist broadcast-pending ZEC leg, but do not mark the cross-asset trade as filled."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO epochs (
            epoch_id, status, clearing_price_usd, total_cleared_zec,
            total_cleared_usd, tx_id, block_hash, quote_batch_id,
            quote_plan_hash, quote_escrow_data_hash, quote_chain_id,
            quote_total_micro, quote_tx_id, target_height,
            consensus_branch_id, intent_ids_json, created_at
        ) VALUES (?, 'ZEC_LEG_PENDING', ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
        ON CONFLICT(epoch_id) DO UPDATE SET
            status='ZEC_LEG_PENDING',
            clearing_price_usd=excluded.clearing_price_usd,
            total_cleared_zec=excluded.total_cleared_zec,
            total_cleared_usd=excluded.total_cleared_usd,
            tx_id=excluded.tx_id,
            block_hash=NULL,
            quote_batch_id=excluded.quote_batch_id,
            quote_plan_hash=excluded.quote_plan_hash,
            quote_escrow_data_hash=excluded.quote_escrow_data_hash,
            quote_chain_id=excluded.quote_chain_id,
            quote_total_micro=excluded.quote_total_micro,
            quote_tx_id=NULL,
            target_height=excluded.target_height,
            consensus_branch_id=excluded.consensus_branch_id,
            intent_ids_json=excluded.intent_ids_json,
            created_at=excluded.created_at
        """,
        (
            epoch_id, clearing_price_usd, total_cleared_zec, total_cleared_usd, tx_id,
            quote_batch_id, quote_plan_hash, quote_escrow_data_hash, quote_chain_id,
            quote_total_micro, target_height, consensus_branch_id,
            json.dumps(sorted(set(intent_ids))), time.time(),
        ),
    )
    for intent_id in intent_ids:
        cur.execute(
            "UPDATE intents SET status = 'ZEC_LEG_PENDING' WHERE intent_id = ? AND epoch_id = ? AND status = 'PENDING'",
            (intent_id, epoch_id),
        )
    cur.execute(
        "INSERT OR IGNORE INTO epochs (epoch_id, status, created_at) VALUES (?, 'ACTIVE', ?)",
        (epoch_id + 1, time.time()),
    )
    conn.commit()
    conn.close()


def record_epoch_zec_confirmed(epoch_id: int, tx_id: str, block_hash: str):
    """Mark only the ZEC leg confirmed; quote settlement still remains pending."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE epochs
        SET status='ZEC_CONFIRMED_QUOTE_PENDING', tx_id=?, block_hash=?
        WHERE epoch_id=? AND status IN ('ZEC_LEG_PENDING', 'ZEC_CONFIRMED_QUOTE_PENDING')
        """,
        (tx_id, block_hash, epoch_id),
    )
    cur.execute(
        """
        UPDATE intents
        SET status='ZEC_CONFIRMED_QUOTE_PENDING'
        WHERE epoch_id=? AND status IN ('ZEC_LEG_PENDING', 'ZEC_CONFIRMED_QUOTE_PENDING')
        """,
        (epoch_id,),
    )
    conn.commit()
    conn.close()


def record_epoch_quote_settled(
    epoch_id: int,
    zec_tx_id: str,
    zec_block_hash: str,
    quote_batch_id: str,
    quote_plan_hash: str,
    quote_total_micro: int,
    quote_tx_id: str,
):
    """Mark FBA intents FILLED only after both ZEC confirmation and on-chain USDC release."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE epochs
        SET status='CLEARED', tx_id=?, block_hash=?, quote_batch_id=?,
            quote_plan_hash=?, quote_total_micro=?, quote_tx_id=?
        WHERE epoch_id=?
          AND status='ZEC_CONFIRMED_QUOTE_PENDING'
          AND tx_id=? AND block_hash=?
          AND quote_batch_id=? AND quote_plan_hash=? AND quote_total_micro=?
        """,
        (
            zec_tx_id, zec_block_hash, quote_batch_id, quote_plan_hash,
            int(quote_total_micro), quote_tx_id, epoch_id, zec_tx_id, zec_block_hash,
            quote_batch_id, quote_plan_hash, int(quote_total_micro),
        ),
    )
    if cur.rowcount != 1:
        conn.rollback()
        conn.close()
        raise RuntimeError("epoch no longer matches the confirmed ZEC transaction and funded quote batch")
    cur.execute(
        """
        UPDATE intents SET status='FILLED'
        WHERE epoch_id=? AND status='ZEC_CONFIRMED_QUOTE_PENDING'
        """,
        (epoch_id,),
    )
    conn.commit()
    conn.close()


def get_epoch_by_txid(tx_id: str) -> Optional[Dict[str, Any]]:
    """Recover the persisted ZEC/USDC association after the API process restarts."""
    if not isinstance(tx_id, str) or not tx_id.strip():
        return None
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM epochs WHERE lower(tx_id) = lower(?) ORDER BY epoch_id DESC LIMIT 1",
        (tx_id.strip(),),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    try:
        record["intent_ids"] = json.loads(record.get("intent_ids_json") or "[]")
    except (TypeError, json.JSONDecodeError):
        record["intent_ids"] = []
    record["txid"] = str(record.get("tx_id") or "").lower()
    return record


def get_epoch_history() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM epochs WHERE status IN ('CLEARED', 'ZEC_LEG_PENDING', 'ZEC_CONFIRMED_QUOTE_PENDING') ORDER BY epoch_id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
