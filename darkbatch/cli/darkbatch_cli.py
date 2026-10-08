#!/usr/bin/env python3
"""
DarkBatch Persistent CLI Tool
Integrated with SQLite storage for stateful operations across multiple terminal sessions.
"""

import argparse
import json
import os
import sys

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from darkbatch.core.repo import (
    list_wallets,
    get_wallet,
    save_intent,
    get_pending_intents,
    mark_intents_settled,
    get_active_epoch_id,
    record_epoch_clear,
    update_wallet_balance
)
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import create_intent, OrderDirection
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon

# Instantiate persistent simulator and solver
NODE = ZcashNodeSimulator()
SOLVER = AutonomousSolverDaemon(NODE)

def main():
    parser = argparse.ArgumentParser(
        description="DarkBatch Persistent CLI - Confidential Batch Auction Protocol for Zcash Ironwood"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Wallet
    p_wallet = subparsers.add_parser("wallet", help="Manage shielded wallets")
    p_wallet.add_argument("subcmd", choices=["list", "balance"])
    p_wallet.add_argument("--alias", type=str, default="alice")

    # Order
    p_order = subparsers.add_parser("order", help="Submit or view shielded swap intents")
    p_order.add_argument("action", choices=["buy", "sell", "list"])
    p_order.add_argument("--alias", type=str, default="alice")
    p_order.add_argument("--amount", type=float, default=5.0)
    p_order.add_argument("--price", type=float, default=42.50)

    # Epoch
    p_epoch = subparsers.add_parser("epoch", help="Inspect or clear batch auction epoch")
    p_epoch.add_argument("action", choices=["status", "clear", "seed"])

    # Node
    p_node = subparsers.add_parser("node", help="Inspect Zcash Ironwood node state")
    p_node.add_argument("action", choices=["info"])

    args = parser.parse_args()

    if args.command == "wallet":
        if args.subcmd == "list":
            wallets = list_wallets()
            print("\n=== REGISTERED SHIELDED WALLETS (Ironwood) ===")
            for w in wallets:
                print(f"[{w['alias'].upper()}] Address: {w['unified_address']}")
                print(f"   Balance: {w['shielded_balance_zec']:.4f} ZEC | ${w['quote_balance_usd']:.2f} USD\n")
        elif args.subcmd == "balance":
            w = get_wallet(args.alias)
            if not w:
                print(f"Wallet '{args.alias}' not found.")
                return
            print(f"[{args.alias.upper()}] Balance: {w.shielded_balance_zec:.4f} ZEC | ${w.quote_balance_usd:.2f} USD")

    elif args.command == "order":
        if args.action in ["buy", "sell"]:
            wallet = get_wallet(args.alias)
            if not wallet:
                print(f"Error: wallet '{args.alias}' not found")
                return
            direction = OrderDirection.BUY_ZEC if args.action == "buy" else OrderDirection.SELL_ZEC
            intent = create_intent(
                direction=direction,
                zec_amount=args.amount,
                limit_price_usd=args.price,
                shielded_address=wallet.unified_address
            )
            epoch_id = get_active_epoch_id()
            save_intent(intent, epoch_id)
            print(f"\n[PERSISTED SHIELDED INTENT CREATED]")
            print(f"Intent ID: {intent.intent_id}")
            print(f"Direction: {intent.direction.value}")
            print(f"Amount:    {intent.base_amount_zec} ZEC")
            print(f"Limit:     ${intent.limit_price_usd}")
            print(f"Commitment:{intent.value_commitment[:24]}...")
            print(f"Epoch:     #{epoch_id}\n")
        elif args.action == "list":
            pending = get_pending_intents()
            print(f"\nPending Intents ({len(pending)} total):")
            for i in pending:
                print(f" - [{i.direction.value}] {i.base_amount_zec} ZEC @ ${i.limit_price_usd} (Address: {i.shielded_address[:28]}...)")

    elif args.command == "epoch":
        epoch_id = get_active_epoch_id()
        if args.action == "status":
            pending = get_pending_intents()
            print(f"Current Epoch: #{epoch_id}")
            print(f"Pending Orders: {len(pending)}")
            for i in pending:
                print(f" * [{i.direction.value}] {i.base_amount_zec} ZEC @ ${i.limit_price_usd}")
        elif args.action == "seed":
            bob = get_wallet("bob")
            alice = get_wallet("alice")
            whale = get_wallet("whale")
            maker = get_wallet("maker")
            save_intent(create_intent(OrderDirection.BUY_ZEC, 15.0, 43.50, bob.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.BUY_ZEC, 25.0, 42.80, whale.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.SELL_ZEC, 20.0, 41.20, alice.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.SELL_ZEC, 15.0, 42.40, maker.unified_address), epoch_id)
            print(f"Seeded 4 realistic orders into Epoch #{epoch_id}.")
        elif args.action == "clear":
            pending = get_pending_intents()
            if not pending:
                print("No pending orders to clear in this epoch.")
                return
            print(f"Solving & Clearing Epoch #{epoch_id} ({len(pending)} orders)...")
            res = SOLVER.run_epoch_settlement(epoch_id, pending)
            
            # Apply wallet balance changes to DB
            if res.get("status") == "SETTLED_AND_MINED":
                record_epoch_clear(
                    epoch_id=epoch_id,
                    clearing_price_usd=res["clearing_price_usd"],
                    total_cleared_zec=res["cleared_zec"],
                    total_cleared_usd=res["cleared_usd"],
                    tx_id=res["tx_id"],
                    block_hash=res["block_hash"]
                )
                mark_intents_settled([i.intent_id for i in pending])
            
            print("\n=== BATCH CLEARING & SETTLEMENT RESULT ===")
            print(json.dumps(res, indent=2))

    elif args.command == "node":
        if args.action == "info":
            info = NODE.get_blockchain_info()
            print(json.dumps(info, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
