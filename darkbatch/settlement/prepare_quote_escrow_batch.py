"""Prepare (but never sign or broadcast) an exact USDC quote-escrow openBatch call.

The output contains EVM addresses and per-fill quote amounts. Keep it private until reviewed.
Use a separate secure wallet/signer to submit the calldata to the deployed escrow contract.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from darkbatch.settlement.quote_escrow import (
    QuoteEscrowError,
    _batch_id_hex,
    _selector,
    quote_escrow_batch_arrays,
    quote_escrow_data_hash,
    quote_plan_hash,
)


def _word_uint(value: int) -> bytes:
    if isinstance(value, bool) or int(value) < 0 or int(value) >= 2**256:
        raise ValueError("ABI uint256 must be an integer in range [0, 2**256)")
    return int(value).to_bytes(32, "big")


def _word_bytes32(value: str, field: str) -> bytes:
    try:
        return bytes.fromhex(_batch_id_hex(value))
    except QuoteEscrowError as exc:
        raise ValueError(f"{field} must be exactly 32-byte hex") from exc


def _word_address(address: str) -> bytes:
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        raise ValueError("all quote addresses must be 20-byte 0x-prefixed EVM addresses")
    try:
        raw = bytes.fromhex(address[2:])
    except ValueError as exc:
        raise ValueError("quote address is not hexadecimal") from exc
    if len(raw) != 20 or raw == bytes(20):
        raise ValueError("quote address must be a non-zero 20-byte EVM address")
    return raw.rjust(32, bytes([0]))


def _array(values: list[Any], encoder) -> bytes:
    return _word_uint(len(values)) + b"".join(encoder(value) for value in values)


def encode_open_batch_calldata(
    batch_id: str, plan_hash: str, arrays: dict[str, list[Any]], deadline: int
) -> str:
    """ABI-encode openBatch(bytes32,bytes32,address[],uint256[],address[],uint256[],uint256)."""
    buyer_addresses = arrays["buyer_addresses"]
    buyer_amounts = arrays["buyer_amounts_micro"]
    seller_addresses = arrays["seller_addresses"]
    seller_amounts = arrays["seller_amounts_micro"]
    if len(buyer_addresses) != len(buyer_amounts) or len(seller_addresses) != len(seller_amounts):
        raise ValueError("quote escrow address and amount array lengths differ")

    tails = [
        _array(buyer_addresses, _word_address),
        _array(buyer_amounts, _word_uint),
        _array(seller_addresses, _word_address),
        _array(seller_amounts, _word_uint),
    ]
    offset = 7 * 32
    offsets: list[bytes] = []
    for tail in tails:
        offsets.append(_word_uint(offset))
        offset += len(tail)

    head = (
        _word_bytes32(batch_id, "batch_id")
        + _word_bytes32(plan_hash, "plan_hash")
        + b"".join(offsets)
        + _word_uint(deadline)
    )
    signature = "openBatch(bytes32,bytes32,address[],uint256[],address[],uint256[],uint256)"
    return "0x" + _selector(signature) + (head + b"".join(tails)).hex()


def build_manifest(plan: dict[str, Any], batch_id: str, deadline: int) -> dict[str, Any]:
    normalized_batch_id = _batch_id_hex(batch_id)
    if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline <= int(time.time()):
        raise ValueError("deadline must be a future Unix timestamp in seconds")
    arrays = quote_escrow_batch_arrays(plan)
    plan_hash = quote_plan_hash(plan)
    data_hash = quote_escrow_data_hash(plan)
    if not arrays["buyer_addresses"] or not arrays["seller_addresses"]:
        raise ValueError("escrow batch must contain buyers and sellers")
    total_buyer_micro = sum(arrays["buyer_amounts_micro"])
    total_seller_micro = sum(arrays["seller_amounts_micro"])
    if total_buyer_micro <= 0 or total_buyer_micro != total_seller_micro:
        raise ValueError("escrow buyer and seller USDC totals must match and be positive")
    return {
        "schema": "darkbatch.quote-escrow-open-batch.v1",
        "batch_id": "0x" + normalized_batch_id,
        "plan_hash": "0x" + plan_hash,
        "escrow_data_hash": "0x" + data_hash,
        "deadline": deadline,
        "buyer_total_micro": total_buyer_micro,
        "seller_total_micro": total_seller_micro,
        **arrays,
        "calldata_hex": encode_open_batch_calldata(
            normalized_batch_id, plan_hash, arrays, deadline
        ),
        "broadcast": False,
        "warning": (
            "Prepared only. Review the full payout manifest and target escrow address; "
            "this tool never signs or broadcasts an EVM transaction."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-json", required=True, type=Path)
    parser.add_argument("--batch-id", required=True, help="Unique 32-byte hex ID, with or without 0x prefix")
    parser.add_argument("--deadline", required=True, type=int, help="Future Unix timestamp in seconds")
    parser.add_argument("--output", required=True, type=Path, help="Private manifest JSON output path")
    args = parser.parse_args()

    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
        if not isinstance(plan, dict):
            raise ValueError("plan JSON root must be an object")
        manifest = build_manifest(plan, args.batch_id, args.deadline)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(args.output, 0o600)
    except (OSError, json.JSONDecodeError, ValueError, QuoteEscrowError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "status": "PREPARED_NOT_BROADCAST",
        "output": str(args.output),
        "batch_id": manifest["batch_id"],
        "plan_hash": manifest["plan_hash"],
        "escrow_data_hash": manifest["escrow_data_hash"],
        "buyer_total_micro": manifest["buyer_total_micro"],
        "seller_total_micro": manifest["seller_total_micro"],
        "calldata_bytes": (len(manifest["calldata_hex"]) - 2) // 2,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
