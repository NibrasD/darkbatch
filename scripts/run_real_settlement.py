#!/usr/bin/env python3
"""
DarkBatch — Real Testnet Settlement Runner
==========================================
Connects a live FBA epoch result to the real Rust PCZT pipeline.

Prerequisites:
  1. zebrad running on testnet (with RPC enabled)
  2. Real testnet ZEC in wallet (get from https://fauzec.com/)
  3. Participant spending key files (one per spend input)
  4. darkbatch_crypto binary built:
       cargo build --release --manifest-path darkbatch_crypto/Cargo.toml

Usage:
  python scripts/run_real_settlement.py <epoch_id> <key_file_1> [key_file_2 ...]

Key file format (JSON, keep offline):
  {"sk_hex": "<64-char hex spending key>"}

Environment variables:
  ZCASH_TESTNET_RPC_URL   (default: http://127.0.0.1:18232)
  ZCASH_TESTNET_RPC_USER
  ZCASH_TESTNET_RPC_PASS
"""

import asyncio
import json
import logging
import os
import sys

import aiohttp

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

API_BASE = os.environ.get("DARKBATCH_API_URL", "http://127.0.0.1:8000")


async def get_local_plan(epoch_id: int) -> dict:
    """Fetch the FBA settlement plan for this epoch from the local API."""
    token = os.environ.get("DARKBATCH_SETTLEMENT_TOKEN", "")
    headers = {"X-Settlement-Token": token} if token else {}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{API_BASE}/api/v1/settlement/local-plan/{epoch_id}",
            headers=headers,
        ) as resp:
            data = await resp.json()
    if "detail" in data:
        raise RuntimeError(f"Could not get local plan: {data['detail']}")
    return data.get("plan", data)


async def get_spendable_notes(rpc_url: str, rpc_user: str, rpc_pass: str) -> list:
    """Get list of spendable Orchard notes from zebrad."""
    auth = aiohttp.BasicAuth(rpc_user, rpc_pass) if rpc_user else None
    async with aiohttp.ClientSession(auth=auth) as session:
        payload = {
            "jsonrpc": "1.0", "id": "darkbatch",
            "method": "z_listunspent",
            "params": [1, 9999999, False, [], "orchard"],
        }
        async with session.post(rpc_url, json=payload) as resp:
            data = await resp.json(content_type=None)
    if data.get("error"):
        raise RuntimeError(f"z_listunspent error: {data['error']}")
    return data["result"]


async def get_anchor(rpc_url: str, rpc_user: str, rpc_pass: str) -> str:
    """Get the current Orchard commitment tree anchor."""
    auth = aiohttp.BasicAuth(rpc_user, rpc_pass) if rpc_user else None
    async with aiohttp.ClientSession(auth=auth) as session:
        # Get latest block height
        payload = {"jsonrpc": "1.0", "id": "darkbatch",
                   "method": "getblockcount", "params": []}
        async with session.post(rpc_url, json=payload) as resp:
            height_data = await resp.json(content_type=None)
        height = height_data["result"]

        # Get tree state for anchor
        payload = {"jsonrpc": "1.0", "id": "darkbatch",
                   "method": "z_gettreestate", "params": [str(height)]}
        async with session.post(rpc_url, json=payload) as resp:
            tree_data = await resp.json(content_type=None)

    orchard_state = tree_data["result"].get("orchard", {})
    anchor = orchard_state.get("commitments", {}).get("finalState")
    if not anchor:
        raise RuntimeError("Could not get Orchard anchor from z_gettreestate")
    return anchor


def build_fba_settlement_json(
    plan: dict,
    notes: list,
    anchor_hex: str,
    target_height: int,
) -> dict:
    """
    Convert the FBA settlement plan + real notes into the PcztBuildRequest
    JSON format expected by the Rust build-fba-pczt-local command.
    """
    inputs = []
    outputs = []
    change_outputs = []

    # Match notes to sell fills
    available_notes = list(notes)
    for fill in plan.get("sell_fills", []):
        needed_zat = fill["filled_zat"]
        addr = fill["shielded_address"]

        # Find notes for this seller
        seller_notes = [n for n in available_notes if n.get("address") == addr]
        if not seller_notes:
            raise ValueError(f"No unspent notes found for seller {addr[:20]}...")

        # Use the first suitable note
        note = seller_notes[0]
        available_notes.remove(note)

        # Build witness path (requires z_getmerklewitness or similar)
        # For now we use the data from z_listunspent
        witness_data = note.get("witness", {})
        path_hex = witness_data.get("path", [])

        if len(path_hex) != 32:
            raise ValueError(
                f"Note witness path must have 32 siblings, got {len(path_hex)}. "
                "Ensure zebrad is synced and note witness is fresh."
            )

        inputs.append({
            "fvk_hex": note.get("fvk_hex", ""),
            "raw_address_hex": note.get("raw_address_hex", ""),
            "value_zat": note["amount"],
            "rho_hex": note.get("rho", ""),
            "rseed_hex": note.get("rseed", ""),
            "merkle_position": note.get("position", 0),
            "merkle_path_hex": path_hex,
        })

        # Change output for this seller
        change_zat = note["amount"] - needed_zat
        if change_zat < 0:
            raise ValueError(f"Note value {note['amount']} < fill {needed_zat}")
        change_outputs.append({
            "fvk_hex": note.get("fvk_hex", ""),
            "raw_address_hex": note.get("raw_address_hex", ""),
            "value_zat": change_zat if change_zat > 0 else None,
            "seller_fill_zat": needed_zat,
            "memo_hex": "",
        })

    # Buyer outputs
    for fill in plan.get("buy_fills", []):
        outputs.append({
            "address_raw_hex": fill.get("raw_address_hex", fill["shielded_address"]),
            "value_zat": fill["filled_zat"],
            "memo_hex": "",  # memo will be encrypted with settlement receipt
        })

    return {
        "target_height": target_height,
        "ironwood_anchor_hex": anchor_hex,
        "inputs": inputs,
        "outputs": outputs,
        "change_outputs": change_outputs,
        "solver_fee_output_zat": int(plan.get("solver_fee_zec", 0) * 1e8),
    }


async def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    epoch_id = int(sys.argv[1])
    key_files = sys.argv[2:]

    rpc_url = os.environ.get("ZCASH_TESTNET_RPC_URL", "http://127.0.0.1:18232")
    rpc_user = os.environ.get("ZCASH_TESTNET_RPC_USER", "")
    rpc_pass = os.environ.get("ZCASH_TESTNET_RPC_PASS", "")

    # Validate key files exist
    for kf in key_files:
        if not os.path.isfile(kf):
            logger.error("Key file not found: %s", kf)
            sys.exit(1)
        with open(kf) as f:
            kdata = json.load(f)
        if "sk_hex" not in kdata:
            logger.error("Key file %s must contain {\"sk_hex\": \"...\"}", kf)
            sys.exit(1)

    logger.info("Step 1: Fetching FBA settlement plan for epoch %d", epoch_id)
    plan = await get_local_plan(epoch_id)
    logger.info(
        "Plan: %.2f ZEC @ $%.2f, %d buy fills, %d sell fills",
        plan.get("total_cleared_zec", 0),
        plan.get("clearing_price_usd", 0),
        len(plan.get("buy_fills", [])),
        len(plan.get("sell_fills", [])),
    )

    logger.info("Step 2: Fetching real notes and anchor from zebrad")
    notes = await get_spendable_notes(rpc_url, rpc_user, rpc_pass)
    anchor = await get_anchor(rpc_url, rpc_user, rpc_pass)
    logger.info("Found %d unspent Orchard notes, anchor=%s...", len(notes), anchor[:16])

    # Get current height for expiry
    auth = aiohttp.BasicAuth(rpc_user, rpc_pass) if rpc_user else None
    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.post(rpc_url, json={
            "jsonrpc": "1.0", "id": "db",
            "method": "getblockcount", "params": []
        }) as resp:
            height_data = await resp.json(content_type=None)
    current_height = height_data["result"]
    target_height = current_height + 100  # valid for ~100 blocks

    logger.info("Step 3: Building FBA PCZT settlement JSON")
    settlement_json = build_fba_settlement_json(plan, notes, anchor, target_height)

    logger.info("Step 4: Running real PCZT pipeline (build → sign → prove → broadcast)")
    from darkbatch.settlement.real_pczt_settlement import RealPCZTSettlement
    orchestrator = RealPCZTSettlement(rpc_url, rpc_user, rpc_pass)

    result = await orchestrator.settle(settlement_json, key_files)

    print("\n" + "=" * 60)
    print("REAL TESTNET SETTLEMENT COMPLETE")
    print("=" * 60)
    print(json.dumps(result, indent=2))

    txid = result.get("txid")
    if txid:
        print(f"\nVerify on Zcash Testnet explorer:")
        print(f"  https://testnet.zcha.in/transactions/{txid}")
        print(f"  https://zcashblockexplorer.com/transactions/{txid}?network=testnet")

    return result


if __name__ == "__main__":
    asyncio.run(main())
