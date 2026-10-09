#!/usr/bin/env python3
"""
CLI for the local FBA simulation prototype. It does not operate a real Ironwood wallet or consensus node.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from darkbatch.core.repo import (
    list_wallets,
    get_wallet,
    save_intent,
    get_pending_intents,
    mark_intents_settled,
    mark_intents_simulated,
    get_active_epoch_id,
    record_epoch_clear,
    record_epoch_simulation,
    update_wallet_balance
)
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import create_intent, OrderDirection
from darkbatch.core.crypto import decrypt_512_memo, derive_shared_key
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon

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

    # Memo Decrypter
    p_memo = subparsers.add_parser("memo", help="Decrypt 512-byte shielded execution receipt")
    p_memo.add_argument("action", choices=["decrypt"])
    p_memo.add_argument("--alias", type=str, required=True, help="Wallet alias whose IVK should decrypt the memo")
    p_memo.add_argument("--hex", type=str, required=True, help="512-byte encrypted memo hex string")

    # Node
    p_node = subparsers.add_parser("node", help="Inspect local simulation state (not a Zcash node)")
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
            print(f"\n[SEALED LIMIT INTENT COMMITTED TO MEMPOOL]")
            print(f"Intent ID:       {intent.intent_id}")
            print(f"Pallas Commit:   {intent.value_commitment[:32]}...")
            print(f"ZIP-228 bsk:     {hex(intent.bsk_share)[:20]}...")
            print(f"Status:          SEALED_AND_COMMITTED")
            print(f"Epoch:           #{epoch_id}\n")
        elif args.action == "list":
            pending = get_pending_intents()
            print(f"\nConfidential Sealed Mempool ({len(pending)} intents):")
            for i in pending:
                print(f" * [SEALED] ID: {i.intent_id[:16]}... | Commitment: {i.value_commitment[:24]}... | Expires: #{i.expiry_height}")

    elif args.command == "epoch":
        epoch_id = get_active_epoch_id()
        if args.action == "status":
            pending = get_pending_intents()
            print(f"Current Epoch: #{epoch_id}")
            print(f"Sealed Orders: {len(pending)}")
            for i in pending:
                print(f" * [SEALED] ID: {i.intent_id[:16]}... | Commitment: {i.value_commitment[:24]}...")
        elif args.action == "seed":
            bob = get_wallet("bob")
            alice = get_wallet("alice")
            whale = get_wallet("whale")
            maker = get_wallet("maker")
            save_intent(create_intent(OrderDirection.BUY_ZEC, 15.0, 43.50, bob.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.BUY_ZEC, 25.0, 42.80, whale.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.SELL_ZEC, 20.0, 41.20, alice.unified_address), epoch_id)
            save_intent(create_intent(OrderDirection.SELL_ZEC, 15.0, 42.40, maker.unified_address), epoch_id)
            print(f"Seeded 4 sealed orders into Epoch #{epoch_id} (Concealed with Pallas commitments).")
        elif args.action == "clear":
            pending = get_pending_intents()
            if not pending:
                print("No pending orders to clear in this epoch.")
                return
            print(f"Solving & Clearing Epoch #{epoch_id} ({len(pending)} sealed orders)...")
            all_wallets = {w["unified_address"]: get_wallet(w["alias"]).ivk for w in list_wallets() if get_wallet(w["alias"])}
            res = SOLVER.run_epoch_settlement(epoch_id, pending, wallets_ivk_map=all_wallets)
            
            if res.get("status") == "SETTLED_AND_MINED":
                # Retained only for a future real-node path; current solver cannot return this state.
                record_epoch_clear(
                    epoch_id=epoch_id,
                    clearing_price_usd=res["clearing_price_usd"],
                    total_cleared_zec=res["cleared_zec"],
                    total_cleared_usd=res["cleared_usd"],
                    tx_id=res["tx_id"],
                    block_hash=res["block_hash"]
                )
                mark_intents_settled([i.intent_id for i in pending])
            elif res.get("status") == "SIMULATED_ONLY":
                record_epoch_simulation(
                    epoch_id=epoch_id,
                    clearing_price_usd=res["clearing_price_usd"],
                    total_cleared_zec=res["cleared_zec"],
                    total_cleared_usd=res["cleared_usd"],
                    simulation_id=res["simulation_id"],
                )
                mark_intents_simulated([i.intent_id for i in pending])

            print("\\n=== FBA MATCH RESULT (SIMULATION ONLY) ===")
            print(json.dumps(res, indent=2))

    elif args.command == "memo":
        if args.action == "decrypt":
            wallet = get_wallet(args.alias)
            if not wallet:
                print(f"Wallet '{args.alias}' not found.")
                return
            try:
                memo_bytes = bytes.fromhex(args.hex)
                shared_key = derive_shared_key(wallet.ivk)
                plaintext = decrypt_512_memo(memo_bytes, shared_key)
                receipt = json.loads(plaintext.decode("utf-8"))
                print(f"\n[CONFIDENTIAL 512-BYTE MEMO DECRYPTED VIA {args.alias.upper()}'S IVK]")
                print(json.dumps(receipt, indent=2))
            except Exception as e:
                print(f"Decryption failed: {e}")

    elif args.command == "node":
        if args.action == "info":
            info = NODE.get_blockchain_info()
            print(json.dumps(info, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
