"""
DarkBatch Database Layer
Persistent SQLite storage for Wallets, Encrypted Intents, Epoch Cycles, Blocks, and Spent Nullifiers.
"""

import json
import os
import sqlite3
import time
from typing import Dict, List, Optional, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "darkbatch_state.db")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    # Wallets
    cur.execute("""
    CREATE TABLE IF NOT EXISTS wallets (
        alias TEXT PRIMARY KEY,
        unified_address TEXT UNIQUE,
        seed_hex TEXT,
        ivk_hex TEXT,
        fvk_hex TEXT,
        balance_zat INTEGER DEFAULT 0,
        balance_cents INTEGER DEFAULT 0
    )
    """)

    # Intents
    cur.execute("""
    CREATE TABLE IF NOT EXISTS intents (
        intent_id TEXT PRIMARY KEY,
        direction TEXT,
        base_amount_zat INTEGER,
        limit_price_cents INTEGER,
        shielded_address TEXT,
        quote_address TEXT,
        expiry_height INTEGER,
        value_commitment TEXT,
        bsk_share TEXT,
        auth_pubkey_hex TEXT,
        signature_hex TEXT,
        epoch_id INTEGER,
        status TEXT DEFAULT 'PENDING',
        created_at REAL
    )
    """)

    # Safe migration for existing local database files.
    intent_columns = {row[1] for row in cur.execute("PRAGMA table_info(intents)").fetchall()}
    if "quote_address" not in intent_columns:
        cur.execute("ALTER TABLE intents ADD COLUMN quote_address TEXT")

    # Epochs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS epochs (
        epoch_id INTEGER PRIMARY KEY,
        status TEXT DEFAULT 'ACTIVE',
        clearing_price_usd REAL DEFAULT 0.0,
        total_cleared_zec REAL DEFAULT 0.0,
        total_cleared_usd REAL DEFAULT 0.0,
        tx_id TEXT,
        block_hash TEXT,
        created_at REAL
    )
    """)

    # Safe migration for existing epoch history rows.
    epoch_columns = {row[1] for row in cur.execute("PRAGMA table_info(epochs)").fetchall()}
    for column, declaration in (
        ("quote_batch_id", "TEXT"),
        ("quote_plan_hash", "TEXT"),
        ("quote_escrow_data_hash", "TEXT"),
        ("quote_chain_id", "INTEGER"),
        ("quote_total_micro", "INTEGER"),
        ("quote_tx_id", "TEXT"),
        ("target_height", "INTEGER"),
        ("consensus_branch_id", "TEXT"),
        ("intent_ids_json", "TEXT"),
    ):
        if column not in epoch_columns:
            cur.execute(f"ALTER TABLE epochs ADD COLUMN {column} {declaration}")

    # Blocks
    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT UNIQUE,
        prev_hash TEXT,
        anchor_root TEXT,
        tx_count INTEGER,
        timestamp REAL,
        block_json TEXT
    )
    """)

    # Spent Nullifiers
    cur.execute("""
    CREATE TABLE IF NOT EXISTS spent_nullifiers (
        nullifier_hex TEXT PRIMARY KEY,
        tx_id TEXT,
        block_height INTEGER,
        spent_at REAL
    )
    """)

    conn.commit()
    conn.close()

# Auto-initialize DB on import
init_db()
