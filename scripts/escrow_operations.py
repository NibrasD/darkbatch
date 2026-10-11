#!/usr/bin/env python3
"""
DarkBatch USDC Escrow Operations Utility
High-level production interface for interacting with the DarkBatchEscrow contract:
- deposit_usdc: Approve and lock USDC tokens for a batch auction.
- release_usdc: Authorized oracle attestation release of USDC to payee with EIP-191 signature.
- refund_usdc: Trigger post-deadline refund of locked USDC back to depositor.
- get_escrow_status: Query on-chain escrow state for a batch ID.
- get_usdc_balance: Query ERC-20 USDC balance for an account.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union, Tuple

from web3 import Web3
from web3.contract import Contract
from eth_account import Account
from eth_account.messages import encode_defunct

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("darkbatch.escrow_ops")

ROOT_DIR = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = ROOT_DIR / "contracts"
DEPLOYED_JSON_PATH = CONTRACTS_DIR / "deployed.json"

ESCROW_STATUS_MAP = {
    0: "NONE",
    1: "DEPOSITED",
    2: "RELEASED",
    3: "REFUNDED"
}

def load_deployment_info() -> Dict[str, Any]:
    """Loads contract addresses and ABIs from deployed.json or environment."""
    if not DEPLOYED_JSON_PATH.exists():
        raise FileNotFoundError(
            f"Deployment info not found at {DEPLOYED_JSON_PATH}. Run deploy_escrow.py first."
        )
    with open(DEPLOYED_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def get_web3_and_contracts(
    rpc_url: Optional[str] = None
) -> Tuple[Web3, Contract, Contract, Dict[str, Any]]:
    """Initializes Web3 provider and escrow/usdc contract instances."""
    deploy_info = load_deployment_info()
    url = rpc_url or os.getenv("EVM_RPC_URL", deploy_info["network"].get("rpc_url", "http://127.0.0.1:8545"))

    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise ConnectionError(f"Failed to connect to EVM RPC at {url}")

    escrow_addr = Web3.to_checksum_address(
        os.getenv("ESCROW_CONTRACT_ADDRESS", deploy_info["escrow"]["address"])
    )
    usdc_addr = Web3.to_checksum_address(
        os.getenv("USDC_ADDRESS", deploy_info["usdc"]["address"])
    )

    escrow_abi = deploy_info["escrow"]["abi"]
    usdc_abi = deploy_info["usdc"]["abi"]

    escrow_contract = w3.eth.contract(address=escrow_addr, abi=escrow_abi)
    usdc_contract = w3.eth.contract(address=usdc_addr, abi=usdc_abi)

    return w3, escrow_contract, usdc_contract, deploy_info

def normalize_bytes32(val: Union[str, bytes]) -> bytes:
    """Normalizes a hex string or bytes object into exact 32 bytes."""
    if isinstance(val, str):
        clean_hex = val[2:] if val.startswith("0x") else val
        if len(clean_hex) != 64:
            raise ValueError(f"Hex string for bytes32 must be 64 characters (32 bytes), got {len(clean_hex)}")
        return bytes.fromhex(clean_hex)
    elif isinstance(val, (bytes, bytearray)):
        if len(val) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(val)}")
        return bytes(val)
    else:
        raise TypeError(f"Expected str or bytes for bytes32, got {type(val)}")

def _send_tx(
    w3: Web3,
    tx_params: Dict[str, Any],
    private_key: str,
    timeout: int = 120
) -> Dict[str, Any]:
    """Helper to estimate gas, sign, broadcast and wait for receipt."""
    account = Account.from_key(private_key)
    sender = account.address
    tx_params["from"] = sender
    tx_params["nonce"] = w3.eth.get_transaction_count(sender, "pending")
    tx_params["chainId"] = w3.eth.chain_id

    if "gas" not in tx_params:
        try:
            estimated = w3.eth.estimate_gas(tx_params)
            tx_params["gas"] = int(estimated * 1.3)
        except Exception as e:
            logger.warning(f"Gas estimation fallback: {e}")
            tx_params["gas"] = 1_000_000

    try:
        latest = w3.eth.get_block("latest")
        if "baseFeePerGas" in latest and latest["baseFeePerGas"] is not None:
            base_fee = latest["baseFeePerGas"]
            p_fee = w3.eth.max_priority_fee
            tx_params["maxPriorityFeePerGas"] = p_fee
            tx_params["maxFeePerGas"] = int(base_fee * 1.5) + p_fee
            tx_params.pop("gasPrice", None)
        else:
            tx_params["gasPrice"] = int(w3.eth.gas_price * 1.1)
    except Exception:
        tx_params["gasPrice"] = w3.eth.gas_price

    signed = account.sign_transaction(tx_params)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    logger.info(f"Transaction broadcast: {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    if receipt.get("status") != 1:
        raise RuntimeError(f"Transaction reverted on-chain: {tx_hash.hex()}")
    return receipt

def deposit_usdc(
    batch_id: int,
    amount: int,
    deadline: int,
    depositor_key: str,
    rpc_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Approves USDC spending if needed, then locks amount into escrow for batch_id.
    :param batch_id: Unique batch auction ID.
    :param amount: Amount of USDC to lock (atomic units, 6 decimals).
    :param deadline: Unix timestamp after which funds can be refunded.
    :param depositor_key: Private key of depositor.
    :param rpc_url: Optional RPC endpoint override.
    """
    w3, escrow, usdc, _ = get_web3_and_contracts(rpc_url)
    depositor = Account.from_key(depositor_key).address
    logger.info(f"Initiating deposit for batch {batch_id}: {amount} USDC from {depositor} (deadline: {deadline})")

    # 1. Check current balance
    balance = usdc.functions.balanceOf(depositor).call()
    if balance < amount:
        raise ValueError(
            f"Insufficient USDC balance: has {balance / 1e6:.2f} USDC, needs {amount / 1e6:.2f} USDC"
        )

    # 2. Check and approve allowance
    allowance = usdc.functions.allowance(depositor, escrow.address).call()
    approve_receipt = None
    if allowance < amount:
        logger.info(f"Approving {amount} USDC to escrow {escrow.address}...")
        approve_tx = usdc.functions.approve(escrow.address, amount).build_transaction({
            "from": depositor
        })
        approve_receipt = _send_tx(w3, approve_tx, depositor_key)
        logger.info(f"USDC approved successfully (tx: {approve_receipt['transactionHash'].hex()})")

    # 3. Call depositEscrow
    deposit_tx = escrow.functions.depositEscrow(batch_id, amount, deadline).build_transaction({
        "from": depositor
    })
    deposit_receipt = _send_tx(w3, deposit_tx, depositor_key)
    logger.info(f"Escrow deposit confirmed (tx: {deposit_receipt['transactionHash'].hex()})")

    return {
        "status": "DEPOSITED",
        "batch_id": batch_id,
        "amount": amount,
        "deadline": deadline,
        "depositor": depositor,
        "approve_tx": approve_receipt["transactionHash"].hex() if approve_receipt else None,
        "deposit_tx": deposit_receipt["transactionHash"].hex(),
        "block_number": deposit_receipt["blockNumber"]
    }

def release_usdc(
    batch_id: int,
    payee: str,
    amount: int,
    zcash_txid: Union[str, bytes],
    oracle_key: str,
    rpc_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Signs oracle settlement attestation and calls releaseEscrow on-chain.
    :param batch_id: Unique batch auction ID.
    :param payee: EVM address of recipient seller.
    :param amount: Amount of USDC to release (atomic units).
    :param zcash_txid: 32-byte Zcash transaction ID hex or bytes.
    :param oracle_key: Authorized oracle's private key.
    :param rpc_url: Optional RPC endpoint override.
    """
    w3, escrow, _, _ = get_web3_and_contracts(rpc_url)
    oracle_account = Account.from_key(oracle_key)
    oracle_address = oracle_account.address
    checksum_payee = Web3.to_checksum_address(payee)
    txid_bytes = normalize_bytes32(zcash_txid)

    logger.info(f"Oracle {oracle_address} releasing batch {batch_id}: {amount} USDC to {checksum_payee}")
    logger.info(f"Zcash Anchor TxID: 0x{txid_bytes.hex()}")

    # 1. Verify caller matches authorized oracle
    contract_oracle = escrow.functions.oracle().call()
    if contract_oracle.lower() != oracle_address.lower():
        raise PermissionError(
            f"Signing key {oracle_address} does not match contract oracle {contract_oracle}"
        )

    # 2. Construct canonical digest and EIP-191 signature
    message_hash = Web3.solidity_keccak(
        ["uint256", "address", "uint256", "bytes32", "address", "uint256"],
        [batch_id, checksum_payee, amount, txid_bytes, escrow.address, w3.eth.chain_id]
    )

    # Cross-check with contract view helper
    onchain_hash = escrow.functions.getMessageHash(batch_id, checksum_payee, amount, txid_bytes).call()
    if message_hash != onchain_hash:
        raise ValueError("Calculated message hash does not match contract getMessageHash!")

    signable_message = encode_defunct(primitive=message_hash)
    signed = oracle_account.sign_message(signable_message)
    oracle_signature = signed.signature

    # 3. Call releaseEscrow
    release_tx = escrow.functions.releaseEscrow(
        batch_id,
        checksum_payee,
        amount,
        txid_bytes,
        oracle_signature
    ).build_transaction({
        "from": oracle_address
    })

    receipt = _send_tx(w3, release_tx, oracle_key)
    logger.info(f"Escrow release confirmed (tx: {receipt['transactionHash'].hex()})")

    return {
        "status": "RELEASED",
        "batch_id": batch_id,
        "payee": checksum_payee,
        "amount": amount,
        "zcash_txid": "0x" + txid_bytes.hex(),
        "oracle": oracle_address,
        "signature": "0x" + oracle_signature.hex(),
        "release_tx": receipt["transactionHash"].hex(),
        "block_number": receipt["blockNumber"]
    }

def refund_usdc(
    batch_id: int,
    caller_key: str,
    rpc_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Triggers refund of expired escrow back to depositor. Anyone can call after deadline.
    :param batch_id: Unique batch auction ID.
    :param caller_key: Private key of transaction sender.
    :param rpc_url: Optional RPC endpoint override.
    """
    w3, escrow, _, _ = get_web3_and_contracts(rpc_url)
    caller = Account.from_key(caller_key).address

    # Pre-check deadline
    record = escrow.functions.getEscrow(batch_id).call()
    status_code = record[4]
    deadline = record[3]
    latest_time = w3.eth.get_block("latest")["timestamp"]

    if status_code != 1:  # Not DEPOSITED
        raise ValueError(
            f"Cannot refund batch {batch_id}: status is {ESCROW_STATUS_MAP.get(status_code, status_code)}"
        )
    if latest_time <= deadline:
        raise ValueError(
            f"Deadline has not passed yet. Current block time: {latest_time}, Deadline: {deadline} (Wait {deadline - latest_time}s)"
        )

    logger.info(f"Calling refundEscrow for batch {batch_id} by {caller}...")
    refund_tx = escrow.functions.refundEscrow(batch_id).build_transaction({
        "from": caller
    })

    receipt = _send_tx(w3, refund_tx, caller_key)
    logger.info(f"Escrow refund confirmed (tx: {receipt['transactionHash'].hex()})")

    return {
        "status": "REFUNDED",
        "batch_id": batch_id,
        "refund_tx": receipt["transactionHash"].hex(),
        "block_number": receipt["blockNumber"]
    }

def get_escrow_status(
    batch_id: int,
    rpc_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Queries on-chain state for a given batch escrow.
    :param batch_id: Unique batch auction ID.
    :param rpc_url: Optional RPC endpoint override.
    """
    _, escrow, _, _ = get_web3_and_contracts(rpc_url)
    record = escrow.functions.getEscrow(batch_id).call()

    depositor, amount, b_id, deadline, status_code = record
    return {
        "batch_id": b_id,
        "depositor": depositor,
        "amount": amount,
        "amount_usdc": amount / 1e6,
        "deadline": deadline,
        "status_code": status_code,
        "status": ESCROW_STATUS_MAP.get(status_code, f"UNKNOWN({status_code})")
    }

def get_usdc_balance(
    address: str,
    rpc_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Queries the USDC ERC-20 token balance for an address.
    :param address: EVM account address.
    :param rpc_url: Optional RPC endpoint override.
    """
    _, _, usdc, _ = get_web3_and_contracts(rpc_url)
    checksum = Web3.to_checksum_address(address)
    raw_bal = usdc.functions.balanceOf(checksum).call()
    return {
        "address": checksum,
        "balance_atomic": raw_bal,
        "balance_usdc": raw_bal / 1e6
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DarkBatch USDC Escrow Operations CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status command
    parser_status = subparsers.add_parser("status", help="Get escrow status for a batch")
    parser_status.add_argument("batch_id", type=int, help="Batch ID")

    # balance command
    parser_bal = subparsers.add_parser("balance", help="Get USDC balance of an address")
    parser_bal.add_argument("address", type=str, help="EVM address")

    # deposit command
    parser_dep = subparsers.add_parser("deposit", help="Deposit USDC to escrow")
    parser_dep.add_argument("--batch-id", type=int, required=True, help="Batch ID")
    parser_dep.add_argument("--amount", type=int, required=True, help="Amount in atomic units (6 decimals)")
    parser_dep.add_argument("--timeout", type=int, default=3600, help="Seconds from now for deadline")
    parser_dep.add_argument("--key", type=str, required=True, help="Depositor private key")

    # release command
    parser_rel = subparsers.add_parser("release", help="Release USDC from escrow")
    parser_rel.add_argument("--batch-id", type=int, required=True, help="Batch ID")
    parser_rel.add_argument("--payee", type=str, required=True, help="Payee EVM address")
    parser_rel.add_argument("--amount", type=int, required=True, help="Amount in atomic units")
    parser_rel.add_argument("--zcash-txid", type=str, required=True, help="32-byte Zcash txid hex")
    parser_rel.add_argument("--oracle-key", type=str, required=True, help="Oracle private key")

    # refund command
    parser_ref = subparsers.add_parser("refund", help="Refund expired escrow")
    parser_ref.add_argument("--batch-id", type=int, required=True, help="Batch ID")
    parser_ref.add_argument("--key", type=str, required=True, help="Caller private key")

    args = parser.parse_args()

    try:
        if args.command == "status":
            res = get_escrow_status(args.batch_id)
            print(json.dumps(res, indent=2))
        elif args.command == "balance":
            res = get_usdc_balance(args.address)
            print(json.dumps(res, indent=2))
        elif args.command == "deposit":
            deadline = int(time.time()) + args.timeout
            res = deposit_usdc(args.batch_id, args.amount, deadline, args.key)
            print(json.dumps(res, indent=2))
        elif args.command == "release":
            res = release_usdc(args.batch_id, args.payee, args.amount, args.zcash_txid, args.oracle_key)
            print(json.dumps(res, indent=2))
        elif args.command == "refund":
            res = refund_usdc(args.batch_id, args.key)
            print(json.dumps(res, indent=2))
    except Exception as e:
        logger.error(f"Command execution error: {e}", exc_info=True)
        sys.exit(1)
