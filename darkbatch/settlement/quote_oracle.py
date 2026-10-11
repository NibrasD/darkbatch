"""Local, opt-in Oracle bridge from a Zebra-confirmed ZEC transaction to the USDC escrow.

Default mode performs read-only checks and prints a reviewed action plan. EVM broadcasts require
--submit and a local DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY. The key is never sent to the coordinator.
The EVM contract remains a trust boundary; this tool does not replace a security audit.
"""
from __future__ import annotations

import argparse
import datetime as dt
import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

from darkbatch.settlement.quote_escrow import (
    QuoteEscrowError,
    STATUS_FUNDED,
    STATUS_RELEASED,
    STATUS_ZEC_CONFIRMED,
    _batch_id_hex,
    _config,
    _read_batch,
    _rpc,
    _selector,
    _keccak256_hex,
    quote_escrow_data_hash,
    quote_plan_hash,
)

TESTNET_NU6_3_HEIGHT = 4_134_000


class OracleError(RuntimeError):
    pass


def _hash32(value: Any, field: str) -> str:
    try:
        return _batch_id_hex(str(value))
    except QuoteEscrowError as exc:
        raise OracleError(f"{field} must be 32-byte hexadecimal text") from exc


def _zcash_rpc(method: str, params: list[Any]) -> Any:
    url = os.getenv("ZCASH_TESTNET_RPC_URL", "").strip()
    if not url:
        raise OracleError("ZCASH_TESTNET_RPC_URL is not configured for the local Zebra node")
    payload = {"jsonrpc": "1.0", "id": "darkbatch-local-quote-oracle", "method": method, "params": params}
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    user = os.getenv("ZCASH_TESTNET_RPC_USER", "")
    password = os.getenv("ZCASH_TESTNET_RPC_PASS", "")
    if user and password:
        encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {encoded}")
    try:
        with urllib.request.urlopen(request, timeout=8.0) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise OracleError(f"Zebra RPC {method} HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise OracleError(f"Zebra RPC {method} failed: {exc}") from exc
    if result.get("error") is not None or "result" not in result:
        raise OracleError(f"Zebra RPC {method} returned an error: {result.get('error')}")
    return result["result"]


def verify_zebra_confirmation(txid: str, minimum_confirmations: int) -> dict[str, Any]:
    normalized_txid = _hash32(txid, "ZEC TXID")
    if minimum_confirmations < 2:
        raise OracleError("minimum ZEC confirmations must be at least two before USDC release")

    chain = _zcash_rpc("getblockchaininfo", [])
    network = _zcash_rpc("getnetworkinfo", [])
    if str(chain.get("chain", "")).lower() not in {"test", "testnet"}:
        raise OracleError("configured Zcash node is not on Testnet")
    if "zebra" not in str(network.get("subversion", "")).lower():
        raise OracleError("configured Zcash Testnet RPC does not identify itself as Zebra")
    tip_height = int(chain.get("blocks", -1))
    if tip_height < TESTNET_NU6_3_HEIGHT:
        raise OracleError("Zebra Testnet tip is before NU6.3 activation")

    transaction = _zcash_rpc("getrawtransaction", [normalized_txid, 1])
    if not isinstance(transaction, dict):
        raise OracleError("Zebra did not return verbose transaction details")
    if _hash32(transaction.get("txid", ""), "Zebra-returned TXID") != normalized_txid:
        raise OracleError("Zebra returned a different transaction ID")
    block_hash = _hash32(transaction.get("blockhash", ""), "ZEC block hash")
    header = _zcash_rpc("getblockheader", [block_hash, True])
    if not isinstance(header, dict) or _hash32(header.get("hash", ""), "Zebra block header hash") != block_hash:
        raise OracleError("Zebra block header does not match the transaction's block hash")
    block_height = int(header.get("height", -1))
    confirmations = tip_height - block_height + 1
    reported_confirmations = int(transaction.get("confirmations", 0))
    if block_height < TESTNET_NU6_3_HEIGHT or confirmations < minimum_confirmations:
        raise OracleError(
            f"ZEC transaction has {confirmations} computed confirmation(s); "
            f"{minimum_confirmations} required"
        )
    if reported_confirmations > 0 and reported_confirmations < minimum_confirmations:
        raise OracleError("Zebra's transaction confirmation count disagrees with the minimum policy")
    return {
        "txid": normalized_txid,
        "block_hash": block_hash,
        "block_height": block_height,
        "tip_height": tip_height,
        "confirmations": confirmations,
        "network": chain["chain"],
        "zebra_subversion": network["subversion"],
    }


def _coordinator_transaction(api_base: str, token: str, txid: str) -> dict[str, Any]:
    if not api_base.startswith("https://") and not api_base.startswith("http://127.0.0.1") and not api_base.startswith("http://localhost"):
        raise OracleError("remote coordinator API must use HTTPS")
    url = api_base.rstrip("/") + "/api/v1/settlement/tx/" + txid
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "X-DarkBatch-Settlement-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OracleError(f"could not fetch coordinator's tracked ZEC transaction: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("transaction"), dict):
        data = data["transaction"]
    if not isinstance(data, dict):
        raise OracleError("coordinator transaction endpoint returned an invalid response")
    return data


def verify_epoch_association(
    record: dict[str, Any],
    epoch_id: int,
    batch_id: str,
    tx: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    if str(record.get("status", "")).upper() != "CONFIRMED":
        raise OracleError("coordinator has not recorded a real confirmed ZEC transaction")
    if int(record.get("confirmations", 0)) < 1:
        raise OracleError("coordinator record does not report a real confirmation")
    if int(record.get("epoch_id", -1)) != epoch_id:
        raise OracleError("ZEC transaction belongs to a different DarkBatch epoch")
    if _hash32(record.get("txid", ""), "coordinator TXID") != tx["txid"]:
        raise OracleError("coordinator TXID does not match Zebra's confirmed transaction")
    if _hash32(record.get("block_hash", ""), "coordinator block hash") != tx["block_hash"]:
        raise OracleError("coordinator block hash does not match Zebra")
    if _batch_id_hex(str(record.get("quote_batch_id", ""))) != _batch_id_hex(batch_id):
        raise OracleError("coordinator transaction references a different USDC batch")
    if str(record.get("quote_plan_hash", "")).lower().removeprefix("0x") != quote_plan_hash(plan):
        raise OracleError("coordinator transaction is associated with a different quote plan")
    if str(record.get("quote_escrow_data_hash", "")).lower().removeprefix("0x") != quote_escrow_data_hash(plan):
        raise OracleError("coordinator transaction is associated with different USDC payout addresses/amounts")


def _oracle_address_from_contract(cfg: dict[str, Any]) -> str:
    result = _rpc(cfg["rpc_url"], "eth_call", [{
        "to": cfg["escrow_address"],
        "data": "0x" + _selector("oracle()"),
    }, "latest"])
    if not isinstance(result, str) or len(result.removeprefix("0x")) < 64:
        raise OracleError("escrow contract does not expose its oracle() address")
    return "0x" + result.removeprefix("0x")[-40:].lower()


def _minimum_evm_confirmations() -> int:
    try:
        value = int(os.getenv("DARKBATCH_QUOTE_MIN_CONFIRMATIONS", "2"))
    except ValueError as exc:
        raise OracleError("DARKBATCH_QUOTE_MIN_CONFIRMATIONS must be an integer >= 2") from exc
    if value < 2:
        raise OracleError("DARKBATCH_QUOTE_MIN_CONFIRMATIONS cannot be lower than two confirmations")
    return value


def _wait_for_evm_receipt(tx_hash: str, cfg: dict[str, Any], wait_seconds: int) -> dict[str, Any]:
    """Poll one existing transaction until its successful receipt reaches the EVM finality policy."""
    normalized_hash = _hash32(tx_hash, "EVM transaction hash")
    if wait_seconds < 0:
        raise OracleError("EVM receipt wait timeout must not be negative")
    minimum_confirmations = _minimum_evm_confirmations()
    deadline = time.monotonic() + wait_seconds
    last_confirmations = 0
    while True:
        receipt = _rpc(cfg["rpc_url"], "eth_getTransactionReceipt", ["0x" + normalized_hash])
        if isinstance(receipt, dict):
            if int(str(receipt.get("status", "0x0")), 16) != 1:
                raise OracleError(
                    f"EVM transaction mined but reverted: 0x{normalized_hash}; "
                    "inspect escrow state before submitting a replacement"
                )
            block_number = int(str(receipt.get("blockNumber", "0x0")), 16)
            tip = int(_rpc(cfg["rpc_url"], "eth_blockNumber", []), 16)
            last_confirmations = max(0, tip - block_number + 1)
            if last_confirmations >= minimum_confirmations:
                return {
                    "status": "EVM_TRANSACTION_CONFIRMED",
                    "transaction_hash": "0x" + normalized_hash,
                    "block_number": block_number,
                    "confirmations": last_confirmations,
                    "required_confirmations": minimum_confirmations,
                }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "status": "EVM_TRANSACTION_PENDING",
                "transaction_hash": "0x" + normalized_hash,
                "confirmations": last_confirmations,
                "required_confirmations": minimum_confirmations,
                "note": "The existing transaction lacks a successful receipt at the required EVM confirmation depth; no replacement was submitted.",
            }
        time.sleep(min(2.0, remaining))


def _write_transaction_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_transaction_state(path: Path, context: Dict[str, Any]) -> Dict[str, Any]:
    if path.is_file():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OracleError("saved EVM transaction state is unreadable; do not create a replacement transaction") from exc
        if not isinstance(state, dict) or state.get("schema") != "darkbatch.evm-signed-transactions.v2":
            raise OracleError("saved EVM transaction state has an unsupported schema")
        for key, expected in context.items():
            if state.get(key) != expected:
                raise OracleError("saved EVM transaction state belongs to a different " + key)
        if not isinstance(state.get("transactions"), dict):
            raise OracleError("saved EVM transaction state has no transaction map")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return state
    state = {
        "schema": "darkbatch.evm-signed-transactions.v2",
        **context,
        "transactions": {},
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    _write_transaction_state(path, state)
    return state


def _recover_or_submit_signed_evm_transaction(
    stage: str,
    calldata: str,
    private_key: str,
    cfg: dict[str, Any],
    wait_seconds: int,
    state_path: Path,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist exact signed bytes before broadcast and recover only that transaction on retry."""
    try:
        from eth_account import Account
    except ImportError as exc:
        raise OracleError("EVM signing requires eth-account; install it in the trusted local environment") from exc
    account = Account.from_key(private_key)
    actual_chain_id = int(_rpc(cfg["rpc_url"], "eth_chainId", []), 16)
    if actual_chain_id != cfg["chain_id"]:
        raise OracleError("EVM signer RPC is connected to a different chain ID than configured")

    state = _load_transaction_state(state_path, context)
    record = state["transactions"].get(stage)
    if record is None:
        nonce = int(_rpc(cfg["rpc_url"], "eth_getTransactionCount", [account.address, "pending"]), 16)
        gas_price = int(_rpc(cfg["rpc_url"], "eth_gasPrice", []), 16)
        call = {"from": account.address, "to": cfg["escrow_address"], "data": calldata, "value": "0x0"}
        gas_estimate = int(_rpc(cfg["rpc_url"], "eth_estimateGas", [call]), 16)
        transaction = {
            "chainId": actual_chain_id,
            "nonce": nonce,
            "to": cfg["escrow_address"],
            "value": 0,
            "data": bytes.fromhex(calldata.removeprefix("0x")),
            "gas": (gas_estimate * 130) // 100 + 10_000,
            "gasPrice": gas_price,
        }
        signed = Account.sign_transaction(transaction, private_key)
        raw = getattr(signed, "raw_transaction", None)
        if raw is None:
            raw = getattr(signed, "rawTransaction", None)
        if raw is None:
            raise OracleError("eth-account did not return signed raw transaction bytes")
        raw_hex = "0x" + bytes(raw).hex()
        tx_hash = "0x" + _keccak256_hex(bytes(raw))
        record = {
            "transaction_hash": tx_hash,
            "raw_transaction_hex": raw_hex,
            "status": "EVM_TRANSACTION_SIGNED",
            "stage": stage,
            "from": account.address.lower(),
            "to": cfg["escrow_address"].lower(),
            "chain_id": actual_chain_id,
            "nonce": nonce,
            "calldata_hash": "0x" + _keccak256_hex(bytes.fromhex(calldata.removeprefix("0x"))),
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        state["transactions"][stage] = record
        _write_transaction_state(state_path, state)

    if not isinstance(record, dict) or record.get("stage") != stage:
        raise OracleError("saved EVM transaction stage is malformed; refusing to create a replacement")
    expected_calldata_hash = "0x" + _keccak256_hex(bytes.fromhex(calldata.removeprefix("0x")))
    try:
        saved_nonce = int(record.get("nonce", -1))
        saved_chain_id = int(record.get("chain_id", -1))
    except (TypeError, ValueError) as exc:
        raise OracleError("saved EVM transaction has invalid nonce/chain metadata") from exc
    if (
        str(record.get("from", "")).lower() != account.address.lower()
        or str(record.get("to", "")).lower() != cfg["escrow_address"].lower()
        or saved_chain_id != actual_chain_id
        or saved_nonce < 0
        or str(record.get("calldata_hash", "")).lower() != expected_calldata_hash.lower()
    ):
        raise OracleError("saved EVM transaction signer, destination, chain, nonce, or call data do not match this settlement stage")
    tx_hash = "0x" + _hash32(record.get("transaction_hash", ""), stage + " transaction hash")
    raw_hex = str(record.get("raw_transaction_hex", ""))
    if not raw_hex.startswith("0x") or len(raw_hex) <= 2 or len(raw_hex[2:]) % 2:
        raise OracleError("saved " + stage + " transaction has no valid signed bytes; refusing to create a replacement")
    try:
        raw = bytes.fromhex(raw_hex[2:])
    except ValueError as exc:
        raise OracleError("saved " + stage + " signed bytes are malformed") from exc
    if "0x" + _keccak256_hex(raw) != tx_hash:
        raise OracleError("saved " + stage + " signed bytes do not match their transaction hash")
    try:
        recovered_signer = Account.recover_transaction(raw)
    except Exception as exc:
        raise OracleError("saved " + stage + " signed transaction cannot be decoded/verified") from exc
    if recovered_signer.lower() != account.address.lower():
        raise OracleError("saved " + stage + " signed transaction was not signed by the configured oracle")

    receipt = _rpc(cfg["rpc_url"], "eth_getTransactionReceipt", [tx_hash])
    if not isinstance(receipt, dict):
        pending = _rpc(cfg["rpc_url"], "eth_getTransactionByHash", [tx_hash])
        if not isinstance(pending, dict):
            try:
                broadcast_hash = _hash32(
                    str(_rpc(cfg["rpc_url"], "eth_sendRawTransaction", [raw_hex])),
                    "rebroadcast transaction hash",
                )
                if "0x" + broadcast_hash != tx_hash:
                    raise OracleError("RPC returned a different hash for the saved signed bytes")
                record["last_broadcast_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                record["status"] = "EVM_TRANSACTION_SUBMITTED"
                _write_transaction_state(state_path, state)
            except (OracleError, QuoteEscrowError):
                # RPCs can answer "already known" or time out even when accepted. Inspect the
                # exact saved hash again; never rebuild with a new nonce as a recovery strategy.
                pending = _rpc(cfg["rpc_url"], "eth_getTransactionByHash", [tx_hash])
                receipt = _rpc(cfg["rpc_url"], "eth_getTransactionReceipt", [tx_hash])
                if not isinstance(pending, dict) and not isinstance(receipt, dict):
                    record["status"] = "EVM_TRANSACTION_PENDING"
                    record["last_error_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                    _write_transaction_state(state_path, state)
                    return {
                        "status": "EVM_TRANSACTION_PENDING",
                        "transaction_hash": tx_hash,
                        "note": "The exact signed transaction remains saved but is not yet visible; no new nonce or replacement was created.",
                    }
        receipt = _rpc(cfg["rpc_url"], "eth_getTransactionReceipt", [tx_hash])

    result = _wait_for_evm_receipt(tx_hash, cfg, wait_seconds)
    record["status"] = result["status"]
    record["last_checked_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    record["confirmations"] = result.get("confirmations", 0)
    _write_transaction_state(state_path, state)
    return {
        **result,
        "from": account.address,
        "to": cfg["escrow_address"],
        "chain_id": actual_chain_id,
    }


def _send_evm_transaction(
    calldata: str,
    private_key: str,
    cfg: dict[str, Any],
    wait_seconds: int,
) -> dict[str, Any]:
    try:
        from eth_account import Account
    except ImportError as exc:
        raise OracleError("EVM signing requires eth-account; install it in the trusted local environment") from exc
    account = Account.from_key(private_key)
    actual_chain_id = int(_rpc(cfg["rpc_url"], "eth_chainId", []), 16)
    if actual_chain_id != cfg["chain_id"]:
        raise OracleError("EVM signer RPC is connected to a different chain ID than configured")

    nonce = int(_rpc(cfg["rpc_url"], "eth_getTransactionCount", [account.address, "pending"]), 16)
    gas_price = int(_rpc(cfg["rpc_url"], "eth_gasPrice", []), 16)
    call = {
        "from": account.address,
        "to": cfg["escrow_address"],
        "data": calldata,
        "value": "0x0",
    }
    gas_estimate = int(_rpc(cfg["rpc_url"], "eth_estimateGas", [call]), 16)
    transaction = {
        "chainId": actual_chain_id,
        "nonce": nonce,
        "to": cfg["escrow_address"],
        "value": 0,
        "data": bytes.fromhex(calldata.removeprefix("0x")),
        "gas": (gas_estimate * 130) // 100 + 10_000,
        "gasPrice": gas_price,
    }
    signed = Account.sign_transaction(transaction, private_key)
    raw = getattr(signed, "raw_transaction", None)
    if raw is None:
        raw = getattr(signed, "rawTransaction", None)
    if raw is None:
        raise OracleError("eth-account did not return signed raw transaction bytes")
    submitted = str(_rpc(cfg["rpc_url"], "eth_sendRawTransaction", ["0x" + bytes(raw).hex()])).lower()
    normalized_txid = _hash32(submitted, "EVM transaction hash")
    result: dict[str, Any] = {
        "status": "EVM_TRANSACTION_SUBMITTED",
        "transaction_hash": "0x" + normalized_txid,
        "from": account.address,
        "to": cfg["escrow_address"],
        "chain_id": actual_chain_id,
    }
    if wait_seconds <= 0:
        return result

    receipt_result = _wait_for_evm_receipt(normalized_txid, cfg, wait_seconds)
    result["status"] = receipt_result["status"]
    if "block_number" in receipt_result:
        result["block_number"] = receipt_result["block_number"]
    if "note" in receipt_result:
        result["note"] = receipt_result["note"]
    return result


def run(
    api_base: str,
    epoch_id: int,
    batch_id: str,
    txid: str,
    plan: dict[str, Any],
    minimum_zec_confirmations: int,
    submit: bool,
    release_usdc: bool,
    wait_seconds: int,
    resume_result: dict[str, Any] | None = None,
    transaction_state_path: Path | None = None,
) -> dict[str, Any]:
    token = os.getenv("DARKBATCH_SETTLEMENT_TOKEN", "").strip()
    if not token:
        raise OracleError("DARKBATCH_SETTLEMENT_TOKEN is required to verify coordinator association")

    zec = verify_zebra_confirmation(txid, minimum_zec_confirmations)
    coordinator = _coordinator_transaction(api_base, token, zec["txid"])
    verify_epoch_association(coordinator, epoch_id, batch_id, zec, plan)

    cfg = _config()
    batch = _read_batch(batch_id)
    expected_plan_hash = quote_plan_hash(plan)
    expected_data_hash = quote_escrow_data_hash(plan)
    if batch["plan_hash"] != expected_plan_hash or batch["escrow_data_hash"] != expected_data_hash:
        raise OracleError("on-chain escrow commitments do not match the confirmed transaction's FBA plan")
    if batch["status_code"] not in {STATUS_FUNDED, STATUS_ZEC_CONFIRMED, STATUS_RELEASED}:
        raise OracleError(f"USDC escrow is not ready for ZEC confirmation/release (status={batch['status_code']})")
    if batch["status_code"] in {STATUS_ZEC_CONFIRMED, STATUS_RELEASED}:
        if batch["zec_txid"] != zec["txid"] or batch["zec_block_hash"] != zec["block_hash"]:
            raise OracleError("escrow has already been associated with a different ZEC transaction/block")

    result: dict[str, Any] = {
        "status": "READ_ONLY_PREFLIGHT_PASSED",
        "epoch_id": epoch_id,
        "batch_id": "0x" + _batch_id_hex(batch_id),
        "plan_hash": expected_plan_hash,
        "escrow_data_hash": expected_data_hash,
        "zec": zec,
        "coordinator_status": coordinator.get("status"),
        "onchain_escrow_status": batch["status_code"],
        "broadcast": False,
    }
    if not submit:
        if release_usdc:
            raise OracleError("--release-usdc requires --submit")
        result["attestation_calldata"] = None if batch["status_code"] != STATUS_FUNDED else (
            "0x" + _selector("markZecConfirmed(bytes32,bytes32,bytes32)")
            + _batch_id_hex(batch_id) + zec["txid"] + zec["block_hash"]
        )
        result["note"] = "Read-only preflight only. No EVM transaction was signed or broadcast."
        return result

    if resume_result is not None:
        # Local recovery state is only a pointer to already-broadcast EVM transactions.
        # Bind it to this exact ZEC tx, batch, epoch, and both payout commitments before reuse.
        saved_zec = resume_result.get("zec")
        if (
            int(resume_result.get("epoch_id", -1)) != epoch_id
            or _batch_id_hex(str(resume_result.get("batch_id", ""))) != _batch_id_hex(batch_id)
            or not isinstance(saved_zec, dict)
            or _hash32(saved_zec.get("txid", ""), "saved ZEC TXID") != zec["txid"]
            or str(resume_result.get("plan_hash", "")).lower().removeprefix("0x") != expected_plan_hash
            or str(resume_result.get("escrow_data_hash", "")).lower().removeprefix("0x") != expected_data_hash
        ):
            raise OracleError("saved EVM recovery state does not match this epoch, ZEC transaction, or USDC payout commitment")

    private_key = os.getenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "").strip()
    if not private_key:
        raise OracleError("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY is required only for --submit")
    try:
        from eth_account import Account
    except ImportError as exc:
        raise OracleError("EVM signing requires eth-account in the trusted local environment") from exc
    account = Account.from_key(private_key)
    configured_oracle = _oracle_address_from_contract(cfg)
    if account.address.lower() != configured_oracle.lower():
        raise OracleError("local EVM signer is not the oracle address configured in the escrow contract")
    if transaction_state_path is not None:
        transaction_context = {
            "epoch_id": epoch_id,
            "batch_id": "0x" + _batch_id_hex(batch_id),
            "zec_txid": zec["txid"],
            "zec_block_hash": zec["block_hash"],
            "plan_hash": expected_plan_hash,
            "escrow_data_hash": expected_data_hash,
            "evm_chain_id": cfg["chain_id"],
            "escrow_address": cfg["escrow_address"].lower(),
            "oracle_address": account.address.lower(),
        }
        saved_state = _load_transaction_state(transaction_state_path, transaction_context)
    else:
        transaction_context = {}
        saved_state = None

    if batch["status_code"] == STATUS_FUNDED:
        calldata = (
            "0x" + _selector("markZecConfirmed(bytes32,bytes32,bytes32)")
            + _batch_id_hex(batch_id) + zec["txid"] + zec["block_hash"]
        )
        prior_attestation = resume_result.get("attestation_transaction") if isinstance(resume_result, dict) else None
        if (
            isinstance(prior_attestation, dict)
            and prior_attestation.get("status") == "EVM_TRANSACTION_CONFIRMED"
            and prior_attestation.get("transaction_hash")
        ):
            raise OracleError(
                "saved attestation receipt is confirmed but escrow still reports FUNDED; "
                "inspect the contract and saved TX before any retry"
            )
        saved_attestation = (
            saved_state["transactions"].get("attestation")
            if isinstance(saved_state, dict) else None
        )
        if isinstance(prior_attestation, dict) and prior_attestation.get("transaction_hash"):
            if saved_attestation:
                if str(saved_attestation.get("transaction_hash", "")).lower() != str(prior_attestation["transaction_hash"]).lower():
                    raise OracleError("saved attestation hash differs between result and signed-byte state")
                if transaction_state_path is not None:
                    result["attestation_transaction"] = _recover_or_submit_signed_evm_transaction(
                        "attestation", calldata, private_key, cfg, wait_seconds,
                        transaction_state_path, transaction_context,
                    )
                else:
                    receipt_result = _wait_for_evm_receipt(
                        str(prior_attestation["transaction_hash"]), cfg, wait_seconds
                    )
                    result["attestation_transaction"] = {**prior_attestation, **receipt_result}
            else:
                # A previous result hash without matching signed bytes is poll-only. Never
                # construct a replacement because the prior transaction may still be pending.
                receipt_result = _wait_for_evm_receipt(
                    str(prior_attestation["transaction_hash"]), cfg, wait_seconds
                )
                result["attestation_transaction"] = {**prior_attestation, **receipt_result}
        elif transaction_state_path is not None:
            result["attestation_transaction"] = _recover_or_submit_signed_evm_transaction(
                "attestation", calldata, private_key, cfg, wait_seconds,
                transaction_state_path, transaction_context,
            )
        else:
            raise OracleError(
                "--submit requires --transaction-state-json before sending a new EVM attestation; "
                "no transaction was created"
            )
        result["broadcast"] = True
        if result["attestation_transaction"]["status"] != "EVM_TRANSACTION_CONFIRMED":
            result["status"] = "ZEC_CONFIRMED_ON_ZEBRA_EVM_ATTESTATION_PENDING"
            return result
        batch = _read_batch(batch_id)
        if batch["status_code"] != STATUS_ZEC_CONFIRMED or batch["zec_txid"] != zec["txid"] or batch["zec_block_hash"] != zec["block_hash"]:
            raise OracleError("oracle transaction receipt is confirmed, but escrow does not reflect the expected ZEC confirmation")
    else:
        result["attestation_transaction"] = {"status": "ALREADY_ATTESTED", "broadcast": False}

    if release_usdc and batch["status_code"] != STATUS_RELEASED:
        release_data = "0x" + _selector("releaseBatch(bytes32)") + _batch_id_hex(batch_id)
        prior_release = resume_result.get("release_transaction") if isinstance(resume_result, dict) else None
        if (
            isinstance(prior_release, dict)
            and prior_release.get("status") == "EVM_TRANSACTION_CONFIRMED"
            and prior_release.get("transaction_hash")
        ):
            raise OracleError(
                "saved release receipt is confirmed but escrow does not report RELEASED; "
                "inspect the contract and saved TX before any retry"
            )
        if (
            isinstance(prior_release, dict)
            and prior_release.get("status") == "EVM_TRANSACTION_CONFIRMED"
            and prior_release.get("transaction_hash")
        ):
            raise OracleError(
                "saved release receipt is confirmed but escrow does not report RELEASED; "
                "inspect the contract and saved TX before any retry"
            )
        saved_release = (
            saved_state["transactions"].get("release")
            if isinstance(saved_state, dict) else None
        )
        if isinstance(prior_release, dict) and prior_release.get("transaction_hash"):
            if saved_release:
                if str(saved_release.get("transaction_hash", "")).lower() != str(prior_release["transaction_hash"]).lower():
                    raise OracleError("saved release hash differs between result and signed-byte state")
                if transaction_state_path is not None:
                    result["release_transaction"] = _recover_or_submit_signed_evm_transaction(
                        "release", release_data, private_key, cfg, wait_seconds,
                        transaction_state_path, transaction_context,
                    )
                else:
                    result["release_transaction"] = {
                        **prior_release,
                        **_wait_for_evm_receipt(str(prior_release["transaction_hash"]), cfg, wait_seconds),
                    }
            else:
                # A previous result hash without matching signed bytes is poll-only. Never
                # construct a replacement because the prior release may still be pending.
                result["release_transaction"] = {
                    **prior_release,
                    **_wait_for_evm_receipt(str(prior_release["transaction_hash"]), cfg, wait_seconds),
                }
        elif transaction_state_path is not None:
            result["release_transaction"] = _recover_or_submit_signed_evm_transaction(
                "release", release_data, private_key, cfg, wait_seconds,
                transaction_state_path, transaction_context,
            )
        else:
            raise OracleError(
                "--submit --release-usdc requires --transaction-state-json before sending a new EVM release; "
                "no transaction was created"
            )
        result["broadcast"] = True
        if result["release_transaction"]["status"] != "EVM_TRANSACTION_CONFIRMED":
            result["status"] = "ZEC_ATTESTED_USDC_RELEASE_PENDING"
            return result
        batch = _read_batch(batch_id)
        if batch["status_code"] != STATUS_RELEASED:
            raise OracleError("release transaction receipt is confirmed, but escrow does not report RELEASED")
    if batch["status_code"] == STATUS_RELEASED:
        # A released contract state is not enough for coordinator finalization: recover the
        # exact release TXID from saved signed-byte state and require the configured EVM depth.
        recovered_release = None
        saved_transactions = saved_state.get("transactions", {}) if isinstance(saved_state, dict) else {}
        saved_release = saved_transactions.get("release") if isinstance(saved_transactions, dict) else None
        previous_release = resume_result.get("release_transaction") if isinstance(resume_result, dict) else None
        release_hash = ""
        if isinstance(saved_release, dict):
            release_hash = str(saved_release.get("transaction_hash", "")).strip()
        if not release_hash and isinstance(previous_release, dict):
            release_hash = str(previous_release.get("transaction_hash", "")).strip()
        if not release_hash:
            result["status"] = "USDC_RELEASED_FINALITY_PENDING"
            result["onchain_escrow_status"] = batch["status_code"]
            result["message"] = (
                "Escrow reports RELEASED, but no saved release transaction hash is available. "
                "Refusing to finalize the coordinator epoch without the exact receipt."
            )
            return result
        receipt_state = _wait_for_evm_receipt(release_hash, cfg, wait_seconds)
        if receipt_state.get("status") != "EVM_TRANSACTION_CONFIRMED":
            result["status"] = "USDC_RELEASED_FINALITY_PENDING"
            result["release_transaction"] = {
                **(saved_release or {}),
                **(previous_release or {}),
                **receipt_state,
            }
            result["onchain_escrow_status"] = batch["status_code"]
            result["message"] = "Escrow reports RELEASED, but the saved release receipt has not reached the required EVM confirmation depth."
            return result
        recovered_release = {
            **(saved_release or {}),
            **(previous_release or {}),
            **receipt_state,
        }
        result["release_transaction"] = recovered_release
        # Preserve attestation reference where available for the audit record.
        saved_attestation = saved_transactions.get("attestation") if isinstance(saved_transactions, dict) else None
        previous_attestation = resume_result.get("attestation_transaction") if isinstance(resume_result, dict) else None
        if isinstance(saved_attestation, dict) and saved_attestation.get("transaction_hash"):
            result["attestation_transaction"] = saved_attestation
        elif isinstance(previous_attestation, dict) and previous_attestation.get("transaction_hash"):
            result["attestation_transaction"] = previous_attestation
        elif isinstance(saved_release, dict) and not recovered_release:
            result["status"] = "USDC_RELEASED_FINALITY_PENDING"
            result["message"] = "Escrow reports RELEASED but a recoverable release receipt hash is missing."
            result["onchain_escrow_status"] = batch["status_code"]
            return result
    result["onchain_escrow_status"] = batch["status_code"]
    result["status"] = "USDC_RELEASED" if batch["status_code"] == STATUS_RELEASED else "ZEC_CONFIRMED_USDC_LOCKED"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--epoch-id", type=int, required=True)
    parser.add_argument("--quote-batch-id", required=True)
    parser.add_argument("--zec-txid", required=True)
    parser.add_argument("--plan-json", type=Path, required=True, help="Exact private plan JSON used by the local settlement agent")
    parser.add_argument("--minimum-zec-confirmations", type=int, default=2)
    parser.add_argument("--wait-seconds", type=int, default=120)
    parser.add_argument("--submit", action="store_true", help="Sign and broadcast the EVM oracle transaction")
    parser.add_argument("--release-usdc", action="store_true", help="After attestation, also call releaseBatch; requires --submit")
    parser.add_argument(
        "--resume-result-json", type=Path, default=None,
        help="Private previous oracle result used to recover a pending EVM transaction",
    )
    parser.add_argument(
        "--transaction-state-json", type=Path, default=None,
        help="Private state file storing exact signed EVM transaction bytes and recovery hashes; required for rebroadcasting the same signed transaction",
    )
    args = parser.parse_args()

    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
        if not isinstance(plan, dict):
            raise ValueError("plan JSON root must be an object")
        if args.submit and args.transaction_state_json is None:
            # Even direct CLI use must persist raw signed bytes before any EVM broadcast.
            args.transaction_state_json = args.plan_json.expanduser().resolve().parent / "usdc-oracle-signed-txs.json"
        resume_result = None
        if args.resume_result_json is not None:
            loaded_resume = json.loads(args.resume_result_json.read_text(encoding="utf-8"))
            if not isinstance(loaded_resume, dict):
                raise ValueError("--resume-result-json must contain a JSON object")
            resume_result = loaded_resume
        result = run(
            args.api_base,
            args.epoch_id,
            args.quote_batch_id,
            args.zec_txid,
            plan,
            args.minimum_zec_confirmations,
            args.submit,
            args.release_usdc,
            args.wait_seconds,
            resume_result=resume_result,
            transaction_state_path=args.transaction_state_json,
        )
    except (OSError, json.JSONDecodeError, ValueError, QuoteEscrowError, OracleError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
