"""Prepare a local FBA fill result plus private wallet notes for the official Rust PCZT builder.

This tool reads the local SQLite epoch by default, or a locally-exported fill JSON, and a
PRIVATE note-scan/receiver file. It only creates a PCZT request manifest and invokes the Rust
builder; it never puts note plaintext, witnesses, viewing keys, or spending keys on the public API.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any


def _zats(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer zatoshi amount")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{field} must be an integer zatoshi amount") from exc
    if number <= 0 or number != value:
        raise ValueError(f"{field} must be a positive integer zatoshi amount")
    return number


def _hex(value: Any, byte_count: int, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hex string")
    normalized = value.strip().lower()
    if len(normalized) != byte_count * 2:
        raise ValueError(f"{field} must be exactly {byte_count} bytes")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hexadecimal") from exc
    return normalized


def _solver_fee_zat(fills: dict[str, Any]) -> int:
    if "solver_fee_zat" in fills:
        value = fills["solver_fee_zat"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("solver_fee_zat must be a non-negative integer")
        return value
    raw = fills.get("solver_fee_zec", 0)
    try:
        fee = Decimal(str(raw)) * Decimal(100_000_000)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("solver_fee_zec must be a non-negative decimal number") from exc
    if not fee.is_finite() or fee < 0:
        raise ValueError("solver_fee_zec must be a finite, non-negative amount")
    return int(fee.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _fill_rows(fills: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = fills.get(key)
    if not isinstance(raw, list):
        raise ValueError(f"fills JSON must contain a {key} array")
    rows = []
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            raise ValueError(f"{key}[{index}] must be an object")
        amount = _zats(row.get("filled_zat"), f"{key}[{index}].filled_zat")
        intent_id = row.get("intent_id")
        address = row.get("shielded_address")
        if not isinstance(intent_id, str) or not intent_id:
            raise ValueError(f"{key}[{index}].intent_id is required")
        if not isinstance(address, str) or not address:
            raise ValueError(f"{key}[{index}].shielded_address is required")
        rows.append({"intent_id": intent_id, "filled_zat": amount, "shielded_address": address})
    return rows


def build_pczt_request(fills: dict[str, Any], wallet_data: dict[str, Any]) -> dict[str, Any]:
    """Map explicit FBA fills and private wallet-scan data into a validated Rust request shape."""
    if not isinstance(wallet_data, dict):
        raise ValueError("private wallet data must be a JSON object")
    target_height = wallet_data.get("target_height")
    if isinstance(target_height, bool) or not isinstance(target_height, int) or target_height < 4_134_000:
        raise ValueError("target_height must be an integer at/above Testnet NU6.3 activation (4134000)")
    anchor = _hex(wallet_data.get("ironwood_anchor_hex"), 32, "ironwood_anchor_hex")

    buys = _fill_rows(fills, "buy_fills")
    sells = _fill_rows(fills, "sell_fills")
    if not buys or not sells:
        raise ValueError("FBA PCZT requires at least one positive buyer fill and seller fill")
    buy_total = sum(row["filled_zat"] for row in buys)
    sell_total = sum(row["filled_zat"] for row in sells)
    if buy_total != sell_total:
        raise ValueError(
            f"unbalanced FBA result: buyer fills total {buy_total} zat, seller fills total {sell_total} zat"
        )

    fee_zat = _solver_fee_zat(fills)
    if fee_zat and fee_zat > sell_total:
        raise ValueError("solver fee exceeds total seller ZEC fills")

    buyer_receivers = wallet_data.get("buyer_receivers")
    seller_change_receivers = wallet_data.get("seller_change_receivers")
    inputs = wallet_data.get("inputs")
    if not isinstance(buyer_receivers, dict):
        raise ValueError("private wallet data must contain a buyer_receivers object keyed by intent_id")
    if not isinstance(seller_change_receivers, dict):
        raise ValueError("private wallet data must contain a seller_change_receivers object keyed by shielded address")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("private wallet data must contain real spendable note inputs")

    outputs = []
    solver_fee_output_index = None
    solver_fee_output_address_raw_hex = ""
    for row in buys:
        receiver = buyer_receivers.get(row["intent_id"])
        if isinstance(receiver, str):
            receiver = {"address_raw_hex": receiver}
        if not isinstance(receiver, dict):
            raise ValueError(f"missing raw Ironwood receiver for buyer intent {row['intent_id']}")
        out = {
            "address_raw_hex": _hex(receiver.get("address_raw_hex"), 43, f"buyer_receivers[{row['intent_id']}].address_raw_hex"),
            "value_zat": row["filled_zat"],
            "memo_hex": receiver.get("memo_hex", ""),
        }
        if not isinstance(out["memo_hex"], str):
            raise ValueError(f"buyer memo for intent {row['intent_id']} must be a hex string")
        outputs.append(out)

    if fee_zat:
        fee_receiver = wallet_data.get("solver_fee_receiver")
        if isinstance(fee_receiver, str):
            fee_receiver = {"address_raw_hex": fee_receiver}
        if not isinstance(fee_receiver, dict):
            raise ValueError("solver_fee_zec is non-zero but solver_fee_receiver is missing from private wallet data")
        memo = fee_receiver.get("memo_hex", "")
        if not isinstance(memo, str):
            raise ValueError("solver_fee_receiver.memo_hex must be a hex string")
        solver_fee_output_index = len(outputs)
        solver_fee_output_address_raw_hex = _hex(
            fee_receiver.get("address_raw_hex"), 43, "solver_fee_receiver.address_raw_hex"
        )
        outputs.append({
            "address_raw_hex": solver_fee_output_address_raw_hex,
            "value_zat": fee_zat,
            "memo_hex": memo,
        })

    # Associate every real input note with the owner identified by the trusted local scanner.
    notes = []
    input_fvk_by_owner: dict[str, str] = {}
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise ValueError(f"inputs[{index}] must be an object")
        owner = item.get("owner_shielded_address")
        if not isinstance(owner, str) or not owner:
            raise ValueError(f"inputs[{index}].owner_shielded_address is required in the private wallet file")
        fvk = _hex(item.get("fvk_hex"), 96, f"inputs[{index}].fvk_hex")
        previous = input_fvk_by_owner.get(owner)
        if previous is not None and previous != fvk:
            raise ValueError(f"local scan maps one owner address to multiple FVKs: {owner}")
        input_fvk_by_owner[owner] = fvk
        if owner not in {row["shielded_address"] for row in sells}:
            raise ValueError(f"input note owner {owner} has no positive seller fill in this FBA result")
        clean = {
            "fvk_hex": fvk,
            "raw_address_hex": _hex(item.get("raw_address_hex"), 43, f"inputs[{index}].raw_address_hex"),
            "value_zat": _zats(item.get("value_zat"), f"inputs[{index}].value_zat"),
            "rho_hex": _hex(item.get("rho_hex"), 32, f"inputs[{index}].rho_hex"),
            "rseed_hex": _hex(item.get("rseed_hex"), 32, f"inputs[{index}].rseed_hex"),
            "merkle_position": item.get("merkle_position"),
            "merkle_path_hex": item.get("merkle_path_hex"),
        }
        if isinstance(clean["merkle_position"], bool) or not isinstance(clean["merkle_position"], int) or clean["merkle_position"] < 0:
            raise ValueError(f"inputs[{index}].merkle_position must be a non-negative integer")
        if not isinstance(clean["merkle_path_hex"], list) or len(clean["merkle_path_hex"]) != 32:
            raise ValueError(f"inputs[{index}].merkle_path_hex must contain exactly 32 sibling hashes")
        clean["merkle_path_hex"] = [
            _hex(sibling, 32, f"inputs[{index}].merkle_path_hex[{sibling_index}]")
            for sibling_index, sibling in enumerate(clean["merkle_path_hex"])
        ]
        notes.append(clean)

    # Aggregate seller fills by actual FVK, not display alias. This guarantees one change
    # destination per owner and keeps multiple aliases for the same wallet consistent.
    seller_fill_by_fvk: dict[str, int] = {}
    change_address_by_fvk: dict[str, str] = {}
    owners_in_result = {row["shielded_address"] for row in sells}
    for owner in owners_in_result:
        if owner not in input_fvk_by_owner:
            raise ValueError(f"seller {owner} has no private spendable notes supplied")
        cfg = seller_change_receivers.get(owner)
        if not isinstance(cfg, dict):
            raise ValueError(f"missing seller-owned change receiver for {owner}")
        fvk = _hex(cfg.get("fvk_hex"), 96, f"seller_change_receivers[{owner}].fvk_hex")
        if fvk != input_fvk_by_owner[owner]:
            raise ValueError(f"seller change FVK does not match the FVK in that owner's input notes: {owner}")
        change_address = _hex(cfg.get("address_raw_hex"), 43, f"seller_change_receivers[{owner}].address_raw_hex")
        old_address = change_address_by_fvk.get(fvk)
        if old_address is not None and old_address != change_address:
            raise ValueError("one FVK maps to multiple change receiver addresses; choose one owner-controlled change address")
        change_address_by_fvk[fvk] = change_address

    base_sells_by_fvk: dict[str, int] = {}
    for row in sells:
        fvk = input_fvk_by_owner[row["shielded_address"]]
        base_sells_by_fvk[fvk] = base_sells_by_fvk.get(fvk, 0) + row["filled_zat"]

    # Largest-remainder fee allocation keeps the output side exactly balanced at one zatoshi.
    fee_shares = {fvk: 0 for fvk in base_sells_by_fvk}
    if fee_zat:
        total_weights = sum(base_sells_by_fvk.values())
        assigned = 0
        remainders = []
        for fvk, weight in base_sells_by_fvk.items():
            q, rem = divmod(weight * fee_zat, total_weights)
            fee_shares[fvk] = q
            assigned += q
            remainders.append((fvk, rem))
        remainders.sort(key=lambda item: (-item[1], item[0]))
        for fvk, _ in remainders[:fee_zat - assigned]:
            fee_shares[fvk] += 1

    change_outputs = []
    for fvk in sorted(base_sells_by_fvk):
        seller_amount = base_sells_by_fvk[fvk]
        change_outputs.append({
            "fvk_hex": fvk,
            "address_raw_hex": change_address_by_fvk[fvk],
            "value_zat": None,
            "seller_fill_zat": seller_amount + fee_shares[fvk],
        })

    seller_input_owners = set(input_fvk_by_owner)
    if seller_input_owners != owners_in_result:
        unused = sorted(seller_input_owners - owners_in_result)
        if unused:
            raise ValueError(f"private note file includes owners with no seller fill: {unused}")

    return {
        "target_height": target_height,
        "ironwood_anchor_hex": anchor,
        "inputs": notes,
        "outputs": outputs,
        "solver_fee_output_zat": fee_zat,
        "solver_fee_output_index": solver_fee_output_index,
        "solver_fee_output_address_raw_hex": solver_fee_output_address_raw_hex,
        "change_fvk_hex": "",
        "change_address_raw_hex": "",
        "change_outputs": change_outputs,
    }


def _local_fba_result() -> dict[str, Any]:
    from darkbatch.core.repo import get_active_epoch_id, get_pending_intents
    from darkbatch.engine.batch_solver import BatchAuctionSolver

    intents = get_pending_intents()
    if not intents:
        raise ValueError("the local SQLite epoch has no pending orders")
    epoch_id = get_active_epoch_id()
    result = BatchAuctionSolver().solve(epoch_id, intents)
    return {
        "epoch_id": result.epoch_id,
        "clearing_price_usd": result.clearing_price_usd,
        "total_cleared_zec": result.total_cleared_zec,
        "total_cleared_usd": result.total_cleared_usd,
        "solver_fee_zec": result.solver_fee_zec,
        "buy_fills": [
            {"intent_id": f.intent_id, "filled_zat": f.filled_zat, "shielded_address": f.shielded_address}
            for f in result.buy_fills
        ],
        "sell_fills": [
            {"intent_id": f.intent_id, "filled_zat": f.filled_zat, "shielded_address": f.shielded_address}
            for f in result.sell_fills
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-data", required=True, help="PRIVATE JSON from the local wallet/scanner containing spendable notes, current witnesses, and raw receiver addresses")
    parser.add_argument("--fills-json", help="Local FBA result JSON; omit to solve the current local SQLite epoch")
    parser.add_argument("--request-output", required=True, help="Path for the PRIVATE PCZT request JSON")
    parser.add_argument("--pczt-output", help="Path for the unsigned PCZT output")
    parser.add_argument("--report-output", help="Path for the PCZT build report")
    parser.add_argument("--rust-binary", default="target/release/darkbatch_crypto")
    parser.add_argument("--prepare-only", action="store_true", help="Write the private request JSON without invoking the Rust PCZT builder")
    args = parser.parse_args()

    try:
        fills = json.loads(Path(args.fills_json).read_text(encoding="utf-8")) if args.fills_json else _local_fba_result()
        wallet_data = json.loads(Path(args.wallet_data).read_text(encoding="utf-8"))
        request = build_pczt_request(fills, wallet_data)
        request_path = Path(args.request_output)
        request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": "PRIVATE_FBA_PCZT_REQUEST_WRITTEN",
            "epoch_id": fills.get("epoch_id"),
            "buy_fill_zat": sum(row["filled_zat"] for row in _fill_rows(fills, "buy_fills")),
            "sell_fill_zat": sum(row["filled_zat"] for row in _fill_rows(fills, "sell_fills")),
            "solver_fee_zat": _solver_fee_zat(fills),
            "input_count": len(request["inputs"]),
            "buyer_output_count": len([o for o in request["outputs"] if o["value_zat"] > 0]) - (1 if _solver_fee_zat(fills) else 0),
            "change_owner_count": len(request["change_outputs"]),
            "request_file": str(request_path),
            "warning": "The request JSON contains sensitive note plaintext/witness data and must remain local. This step does not broadcast or settle USDC."
        }, indent=2))
        if args.prepare_only:
            return 0
        if not args.pczt_output or not args.report_output:
            parser.error("--pczt-output and --report-output are required unless --prepare-only is set")
        completed = subprocess.run(
            [args.rust_binary, "build-fba-pczt-local", str(request_path), args.pczt_output, args.report_output],
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.stdout:
            print(completed.stdout)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        return completed.returncode
    except Exception as exc:
        print(json.dumps({"status": "FBA_PCZT_PREPARATION_FAILED", "error": str(exc), "simulation_used": False}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
