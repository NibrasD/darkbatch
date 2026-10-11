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


def quote_escrow_batch_arrays(plan: Dict[str, Any]) -> Dict[str, list[Any]]:
    """Canonical escrow arrays, aggregated by EVM address exactly like the deployment script.

    The FBA plan hash commits to individual fills. The escrow contract instead records one
    deposit/payout row per EVM address, so its escrowDataHash must be computed from aggregated
    rows or plans with multiple fills for one trader would never pass preflight.
    """
    data = quote_plan_commitment_data(plan)

    def rows(key: str) -> list[dict[str, Any]]:
        amounts_by_address: Dict[str, int] = {}
        for row in data[key]:
            address = str(row["quote_address"]).lower()
            amounts_by_address[address] = (
                amounts_by_address.get(address, 0) + int(row["quote_amount_micro"])
            )
        return [
            {"quote_address": address, "quote_amount_micro": amount}
            for address, amount in sorted(amounts_by_address.items())
        ]

    buyers = rows("buy_fills")
    sellers = rows("sell_fills")
    return {
        "buyer_addresses": [row["quote_address"] for row in buyers],
        "buyer_amounts_micro": [int(row["quote_amount_micro"]) for row in buyers],
        "seller_addresses": [row["quote_address"] for row in sellers],
        "seller_amounts_micro": [int(row["quote_amount_micro"]) for row in sellers],
    }


def _abi_word_uint(value: int) -> bytes:
    if isinstance(value, bool) or int(value) < 0 or int(value) >= 2**256:
        raise QuoteEscrowError("ABI uint256 value is outside its valid range")
    return int(value).to_bytes(32, "big")


def _abi_word_address(value: str) -> bytes:
    if not _ADDRESS_RE.fullmatch(value):
        raise QuoteEscrowError("ABI address array contains an invalid EVM address")
    return bytes.fromhex(value[2:]).rjust(32, bytes([0]))


def _abi_array(values: list[Any], encoder) -> bytes:
    return _abi_word_uint(len(values)) + b"".join(encoder(value) for value in values)


def quote_escrow_data_hash(plan: Dict[str, Any]) -> str:
    """Keccak-256 of abi.encode(buyers, buyerAmounts, sellers, sellerAmounts)."""
    arrays = quote_escrow_batch_arrays(plan)
    tails = [
        _abi_array(arrays["buyer_addresses"], _abi_word_address),
        _abi_array(arrays["buyer_amounts_micro"], _abi_word_uint),
        _abi_array(arrays["seller_addresses"], _abi_word_address),
        _abi_array(arrays["seller_amounts_micro"], _abi_word_uint),
    ]
    offset = 32 * len(tails)
    offsets = []
    for tail in tails:
        offsets.append(_abi_word_uint(offset))
        offset += len(tail)
    encoded = b"".join(offsets) + b"".join(tails)
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise QuoteEscrowError(
            "EVM escrow verification requires pycryptodome; install requirements.txt"
        ) from exc
    digest = keccak.new(digest_bits=256)
    digest.update(encoded)
    return digest.hexdigest()


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


def _keccak256_hex(payload: bytes) -> str:
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise QuoteEscrowError(
            "EVM escrow verification requires pycryptodome; install requirements.txt"
        ) from exc
    digest = keccak.new(digest_bits=256)
    digest.update(payload)
    return digest.hexdigest()


def _selector(signature: str) -> str:
    # keccak-256, as required by the Ethereum ABI (not hashlib.sha3_256).
    return _keccak256_hex(signature.encode("ascii"))[:8]


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
    if len(result.removeprefix("0x")) < 11 * 64:
        raise QuoteEscrowError(
            "escrow does not expose the 11th getBatchStatus word (escrowDataHash); deploy the updated contract"
        )
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
        "escrow_data_hash": _bytes32_word(result, 10),
        "batch_id": "0x" + batch_hex,
        "chain_id": actual_chain,
        "escrow_address": cfg["escrow_address"],
        "expected_token_address": cfg["token_address"],
    }


def verify_funded_quote_batch(batch_id: str, plan: Dict[str, Any]) -> Dict[str, Any]:
    """Refuse ZEC broadcast unless every USDC buyer has locked the exact committed amount."""
    expected_hash = quote_plan_hash(plan)
    expected_data_hash = quote_escrow_data_hash(plan)
    expected_total = int(plan["quote_total_micro"])
    batch = _read_batch(batch_id)
    if batch["status_code"] != STATUS_FUNDED:
        raise QuoteEscrowError(f"USDC escrow batch is not fully funded (status={batch['status_code']})")
    if batch["plan_hash"] != expected_hash:
        raise QuoteEscrowError("USDC escrow plan hash does not match the current signed FBA fill plan")
    if batch["escrow_data_hash"] != expected_data_hash:
        raise QuoteEscrowError("USDC escrow's committed buyer/seller addresses or amounts do not match the FBA plan")
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
        "escrow_data_hash": expected_data_hash,
    }


def verify_released_quote_batch_by_hash(
    batch_id: str,
    expected_plan_hash: str,
    expected_total_micro: int,
    release_txid: str,
    expected_escrow_data_hash: str,
    expected_zec_txid: str,
    expected_zec_block_hash: str,
) -> Dict[str, Any]:
    """Verify an EVM batch is RELEASED for the plan attached to a confirmed ZEC transaction."""
    normalized_hash = str(expected_plan_hash).lower().removeprefix("0x")
    if not _BYTES32_RE.fullmatch(normalized_hash):
        raise QuoteEscrowError("expected FBA plan hash must be 32-byte hex")
    batch = _read_batch(batch_id)
    if batch["status_code"] != STATUS_RELEASED:
        raise QuoteEscrowError(f"USDC escrow has not released payouts (status={batch['status_code']})")
    normalized_data_hash = str(expected_escrow_data_hash).lower().removeprefix("0x")
    if not _BYTES32_RE.fullmatch(normalized_data_hash) or batch["escrow_data_hash"] != normalized_data_hash:
        raise QuoteEscrowError("released USDC buyer/seller amounts differ from the batch verified before ZEC broadcast")
    if batch["plan_hash"] != normalized_hash:
        raise QuoteEscrowError("released USDC batch belongs to a different FBA quote plan")
    if batch["buyer_total_micro"] != int(expected_total_micro) or batch["seller_total_micro"] != int(expected_total_micro):
        raise QuoteEscrowError("released USDC totals do not match the FBA quote")
    if batch["token_address"] != batch["expected_token_address"]:
        raise QuoteEscrowError("released quote batch uses the wrong token contract")
    normalized_zec_txid = _batch_id_hex(expected_zec_txid)
    normalized_zec_block_hash = _batch_id_hex(expected_zec_block_hash)
    if batch["zec_txid"] != normalized_zec_txid or batch["zec_block_hash"] != normalized_zec_block_hash:
        raise QuoteEscrowError("escrow's confirmed ZEC TXID/block hash does not match the confirmed epoch transaction")

    cfg = _config()
    txid = _batch_id_hex(release_txid)
    receipt = _rpc(cfg["rpc_url"], "eth_getTransactionReceipt", ["0x" + txid])
    if not isinstance(receipt, dict) or int(receipt.get("status", "0x0"), 16) != 1:
        raise QuoteEscrowError("USDC release transaction is not confirmed successfully on the EVM network")
    if str(receipt.get("to", "")).lower() != batch["escrow_address"]:
        raise QuoteEscrowError("USDC release receipt was not sent to the configured escrow contract")

    # A generic successful call to the escrow is not proof that this batch was released.
    event_topic = "0x" + _keccak256_hex(b"BatchReleased(bytes32,bytes32)")
    expected_batch_topic = "0x" + _batch_id_hex(batch_id)
    expected_tx_topic = "0x" + normalized_zec_txid
    found_batch_release = False
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if (
            str(log.get("address", "")).lower() == batch["escrow_address"]
            and len(topics) >= 3
            and str(topics[0]).lower() == event_topic
            and str(topics[1]).lower() == expected_batch_topic
            and str(topics[2]).lower() == expected_tx_topic
        ):
            found_batch_release = True
            break
    if not found_batch_release:
        raise QuoteEscrowError("EVM receipt has no BatchReleased event for this exact escrow batch and ZEC TXID")

    # Require a configurable number of EVM confirmations to reduce release-receipt reorg risk.
    try:
        minimum_confirmations = int(os.getenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2"))
        receipt_height = int(str(receipt.get("blockNumber", "0x0")), 16)
        chain_tip = int(_rpc(cfg["rpc_url"], "eth_blockNumber", []), 16)
    except (ValueError, TypeError):
        raise QuoteEscrowError("EVM release receipt has no usable block number or confirmation configuration")
    if minimum_confirmations < 1 or receipt_height <= 0 or chain_tip < receipt_height:
        raise QuoteEscrowError("EVM release receipt block/confirmation configuration is invalid")
    if chain_tip - receipt_height + 1 < minimum_confirmations:
        raise QuoteEscrowError(
            f"USDC release has {chain_tip - receipt_height + 1} EVM confirmation(s); "
            f"{minimum_confirmations} required"
        )
    return {
        "status": "USDC_RELEASED",
        "release_txid": "0x" + txid,
        **batch,
        "plan_hash": normalized_hash,
    }


def verify_released_quote_batch(batch_id: str, plan: Dict[str, Any],
                                release_txid: str) -> Dict[str, Any]:
    """Verify the escrow is RELEASED and the associated EVM release transaction succeeded."""
    expected_hash = quote_plan_hash(plan)
    expected_data_hash = quote_escrow_data_hash(plan)
    batch = _read_batch(batch_id)
    if batch["status_code"] != STATUS_RELEASED:
        raise QuoteEscrowError(f"USDC escrow has not released payouts (status={batch['status_code']})")
    if batch["plan_hash"] != expected_hash:
        raise QuoteEscrowError("released USDC batch belongs to a different FBA quote plan")
    if batch["escrow_data_hash"] != expected_data_hash:
        raise QuoteEscrowError("released USDC buyer/seller addresses or amounts do not match the FBA plan")
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
