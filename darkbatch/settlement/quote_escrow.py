"""
USDC quote-plan hashing and read-only EVM escrow verification.

The coordinator never signs or moves USDC. It checks a deployed DarkBatchQuoteEscrow
contract before it permits the ZEC leg to broadcast, and checks its state again before
the database can mark an FBA trade fully settled.

The escrow oracle is a trust boundary: the EVM contract cannot natively verify a shielded
Zcash transaction. A separate configured oracle/relayer must attest only after Zebra has
reported a real block confirmation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any, Dict, Optional


_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
STATUS_NONE = 0
STATUS_OPEN = 1
STATUS_FUNDED = 2
STATUS_ZEC_CONFIRMED = 3
STATUS_RELEASED = 4
STATUS_REFUNDABLE = 5
STATUS_REFUNDED = 6


class QuoteEscrowError(RuntimeError):
    pass


def _price_string(value: Any) -> str:
    price = Decimal(str(value)).normalize()
    return format(price, "f")


def quote_plan_commitment_data(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical non-secret representation shared by the API, operator, and Solidity batch."""
    def normalized_fills(key: str) -> list[dict[str, Any]]:
        fills = plan.get(key)
        if not isinstance(fills, list):
            raise QuoteEscrowError(f"quote plan is missing {key}")
        result = []
        for fill in fills:
            address = str(fill.get("quote_address") or "").strip()
            if not _ADDRESS_RE.fullmatch(address):
                raise QuoteEscrowError(
                    f"intent {fill.get('intent_id')} has no valid signed EVM quote_address"
                )
            amount = int(fill.get("quote_amount_micro", -1))
            filled_zat = int(fill.get("filled_zat", 0))
            if amount <= 0 or filled_zat <= 0:
                raise QuoteEscrowError("quote amounts and ZEC fill amounts must be positive")
            result.append({
                "intent_id": str(fill["intent_id"]),
                "shielded_address": str(fill["shielded_address"]),
                "quote_address": address.lower(),
                "filled_zat": filled_zat,
                "quote_amount_micro": amount,
            })
        result.sort(key=lambda row: (
            row["quote_address"], row["intent_id"], row["shielded_address"],
            row["filled_zat"], row["quote_amount_micro"],
        ))
        return result

    buy_fills = normalized_fills("buy_fills")
    sell_fills = normalized_fills("sell_fills")
    buy_micro = sum(item["quote_amount_micro"] for item in buy_fills)
    sell_micro = sum(item["quote_amount_micro"] for item in sell_fills)
    expected_micro = int(plan.get("quote_total_micro", -1))
    if expected_micro <= 0 or buy_micro != expected_micro or sell_micro != expected_micro:
        raise QuoteEscrowError(
            f"quote totals do not balance: expected={expected_micro}, buys={buy_micro}, sells={sell_micro}"
        )
    buy_zat = sum(item["filled_zat"] for item in buy_fills)
    sell_zat = sum(item["filled_zat"] for item in sell_fills)
    if buy_zat <= 0 or buy_zat != sell_zat:
        raise QuoteEscrowError("buyer and seller ZEC fills are not equal in integer zatoshi")

    return {
        "schema": "darkbatch.usdc-quote-commitment.v1",
        "epoch_id": int(plan["epoch_id"]),
        "clearing_price_usd": _price_string(plan["clearing_price_usd"]),
        "quote_asset": "USDC",
        "quote_decimals": 6,
        "quote_total_micro": expected_micro,
        "buy_fills": buy_fills,
        "sell_fills": sell_fills,
    }


def quote_plan_hash(plan: Dict[str, Any]) -> str:
    payload = json.dumps(
        quote_plan_commitment_data(plan),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({
            "jsonrpc": "2.0",
            "id": "darkbatch-usdc-escrow",
            "method": method,
            "params": params,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8.0) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise QuoteEscrowError(f"EVM RPC HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise QuoteEscrowError(f"EVM RPC {method} failed: {exc}") from exc
    if result.get("error") is not None:
        raise QuoteEscrowError(f"EVM RPC {method} error: {result['error']}")
    if "result" not in result:
        raise QuoteEscrowError(f"EVM RPC {method} returned no result")
    return result["result"]


def _selector(signature: str) -> str:
    # keccak-256, as required by the Ethereum ABI (not hashlib.sha3_256).
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise QuoteEscrowError(
            "EVM escrow verification requires pycryptodome; install requirements.txt"
        ) from exc
    digest = keccak.new(digest_bits=256)
    digest.update(signature.encode("ascii"))
    return digest.hexdigest()[:8]


def _word(result: str, index: int) -> str:
    normalized = str(result).removeprefix("0x")
    expected_length = 10 * 64
    if len(normalized) < expected_length or len(normalized) % 64 != 0:
        raise QuoteEscrowError("getBatchStatus returned malformed ABI data")
    return normalized[index * 64:(index + 1) * 64]


def _uint_word(result: str, index: int) -> int:
    return int(_word(result, index), 16)


def _bytes32_word(result: str, index: int) -> str:
    return _word(result, index).lower()


def _address_word(result: str, index: int) -> str:
    return "0x" + _word(result, index)[-40:].lower()


def _config() -> Dict[str, Any]:
    rpc_url = os.getenv("DARKBATCH_QUOTE_RPC_URL", "").strip()
    escrow = os.getenv("DARKBATCH_USDC_ESCROW_ADDRESS", "").strip()
    token = os.getenv("DARKBATCH_USDC_TOKEN_ADDRESS", "").strip()
    chain_id = os.getenv("DARKBATCH_QUOTE_CHAIN_ID", "").strip()
    if not rpc_url or not _ADDRESS_RE.fullmatch(escrow) or not _ADDRESS_RE.fullmatch(token) or not chain_id:
        raise QuoteEscrowError(
            "USDC escrow verification is not configured; set DARKBATCH_QUOTE_RPC_URL, "
            "DARKBATCH_QUOTE_CHAIN_ID, DARKBATCH_USDC_TOKEN_ADDRESS, and "
            "DARKBATCH_USDC_ESCROW_ADDRESS after deploying the escrow contract."
        )
    try:
        parsed_chain_id = int(chain_id, 0)
    except ValueError as exc:
        raise QuoteEscrowError("DARKBATCH_QUOTE_CHAIN_ID must be a decimal or 0x-prefixed integer") from exc
    return {
        "rpc_url": rpc_url,
        "escrow_address": escrow.lower(),
        "token_address": token.lower(),
        "chain_id": parsed_chain_id,
    }


def _batch_id_hex(batch_id: str) -> str:
    if not isinstance(batch_id, str) or not _BYTES32_RE.fullmatch(batch_id.strip()):
        raise QuoteEscrowError("quote_batch_id must be 32-byte hex (64 characters, optional 0x prefix)")
    return batch_id.strip().removeprefix("0x").lower()


def _read_batch(batch_id: str) -> Dict[str, Any]:
    cfg = _config()
    batch_hex = _batch_id_hex(batch_id)
    actual_chain = int(_rpc(cfg["rpc_url"], "eth_chainId", []), 16)
    if actual_chain != cfg["chain_id"]:
        raise QuoteEscrowError(
            f"quote RPC chain ID is {actual_chain}, configured chain ID is {cfg['chain_id']}"
        )
    data = "0x" + _selector("getBatchStatus(bytes32)") + batch_hex
    result = _rpc(cfg["rpc_url"], "eth_call", [{
        "to": cfg["escrow_address"],
        "data": data,
    }, "latest"])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise QuoteEscrowError("USDC escrow contract returned no ABI status")
    return {
        "status_code": _uint_word(result, 0),
        "plan_hash": _bytes32_word(result, 1),
        "buyer_total_micro": _uint_word(result, 2),
        "seller_total_micro": _uint_word(result, 3),
        "buyer_count": _uint_word(result, 4),
        "paid_buyer_count": _uint_word(result, 5),
        "deadline": _uint_word(result, 6),
        "token_address": _address_word(result, 7),
        "zec_txid": _bytes32_word(result, 8),
        "zec_block_hash": _bytes32_word(result, 9),
        "batch_id": "0x" + batch_hex,
        "chain_id": actual_chain,
        "escrow_address": cfg["escrow_address"],
        "expected_token_address": cfg["token_address"],
    }


def verify_funded_quote_batch(batch_id: str, plan: Dict[str, Any]) -> Dict[str, Any]:
    """Refuse ZEC broadcast unless every USDC buyer has locked the exact committed amount."""
    expected_hash = quote_plan_hash(plan)
    expected_total = int(plan["quote_total_micro"])
    batch = _read_batch(batch_id)
    if batch["status_code"] != STATUS_FUNDED:
        raise QuoteEscrowError(f"USDC escrow batch is not fully funded (status={batch['status_code']})")
    if batch["plan_hash"] != expected_hash:
        raise QuoteEscrowError("USDC escrow plan hash does not match the current signed FBA fill plan")
    if (
        batch["buyer_total_micro"] != expected_total
        or batch["seller_total_micro"] != expected_total
        or batch["buyer_count"] <= 0
        or batch["paid_buyer_count"] != batch["buyer_count"]
    ):
        raise QuoteEscrowError("USDC escrow is not fully funded for the exact FBA quote amount")
    if batch["token_address"] != batch["expected_token_address"]:
        raise QuoteEscrowError("deployed escrow uses a different token than configured USDC")
    if batch["deadline"] <= int(time.time()):
        raise QuoteEscrowError("USDC escrow deadline has expired")
    return {
        "status": "USDC_LOCKED",
        **batch,
        "plan_hash": expected_hash,
        "quote_total_micro": expected_total,
    }


def verify_released_quote_batch(batch_id: str, plan: Dict[str, Any],
                                release_txid: str) -> Dict[str, Any]:
    """Verify the escrow is RELEASED and the associated EVM release transaction succeeded."""
    expected_hash = quote_plan_hash(plan)
    batch = _read_batch(batch_id)
    if batch["status_code"] != STATUS_RELEASED:
        raise QuoteEscrowError(f"USDC escrow has not released payouts (status={batch['status_code']})")
    if batch["plan_hash"] != expected_hash:
        raise QuoteEscrowError("released USDC batch belongs to a different FBA quote plan")
    if batch["buyer_total_micro"] != int(plan["quote_total_micro"]) or batch["seller_total_micro"] != int(plan["quote_total_micro"]):
        raise QuoteEscrowError("released USDC totals do not match the FBA quote")
    if batch["token_address"] != batch["expected_token_address"]:
        raise QuoteEscrowError("released quote batch uses the wrong token contract")
    txid = _batch_id_hex(release_txid)
    receipt = _rpc(_config()["rpc_url"], "eth_getTransactionReceipt", ["0x" + txid])
    if not isinstance(receipt, dict) or int(receipt.get("status", "0x0"), 16) != 1:
        raise QuoteEscrowError("USDC release transaction is not confirmed successfully on the EVM network")
    return {
        "status": "USDC_RELEASED",
        "release_txid": "0x" + txid,
        **batch,
        "plan_hash": expected_hash,
    }
