#!/usr/bin/env python3
"""
DarkBatch USDC Minting Utility
Mints test USDC tokens to DarkBatch test accounts on EVM testnet.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

from web3 import Web3
from eth_account import Account

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("darkbatch.mint")

ROOT_DIR = Path(__file__).resolve().parent.parent
DEPLOYED_JSON = ROOT_DIR / "contracts" / "deployed.json"

# Standard DarkBatch test accounts (Anvil / Hardhat pre-funded addresses)
DEFAULT_TEST_ACCOUNTS = [
    {"alias": "deployer", "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "amount_usdc": 100_000},
    {"alias": "alice",    "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "amount_usdc": 50_000},
    {"alias": "bob",      "address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "amount_usdc": 50_000},
    {"alias": "whale",    "address": "0x90F79bf6EB2c4f870365E785982E1f101E93b906", "amount_usdc": 250_000},
    {"alias": "maker",    "address": "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", "amount_usdc": 100_000},
]

def mint_usdc_to_accounts(
    accounts: List[Dict[str, Any]] = None,
    rpc_url: str = None,
    deployer_key: str = None
) -> List[Dict[str, Any]]:
    if not DEPLOYED_JSON.exists():
        raise FileNotFoundError(f"Missing {DEPLOYED_JSON}. Run deploy_escrow.py first.")

    with open(DEPLOYED_JSON, "r", encoding="utf-8") as f:
        deploy_info = json.load(f)

    url = rpc_url or os.getenv("EVM_RPC_URL", deploy_info["network"].get("rpc_url", "http://127.0.0.1:8545"))
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise ConnectionError(f"Could not connect to {url}")

    key = deployer_key or os.getenv("DEPLOYER_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
    sender = Account.from_key(key).address

    usdc_addr = Web3.to_checksum_address(deploy_info["usdc"]["address"])
    usdc_abi = deploy_info["usdc"]["abi"]
    usdc_contract = w3.eth.contract(address=usdc_addr, abi=usdc_abi)

    targets = accounts or DEFAULT_TEST_ACCOUNTS
    results = []

    logger.info(f"Minting USDC tokens via {usdc_addr} from {sender}...")

    for acc in targets:
        recipient = Web3.to_checksum_address(acc["address"])
        amount_atomic = int(acc["amount_usdc"] * 10**6)

        try:
            # Check if mint method exists on contract
            if hasattr(usdc_contract.functions, "mint"):
                tx = usdc_contract.functions.mint(recipient, amount_atomic).build_transaction({
                    "from": sender,
                    "nonce": w3.eth.get_transaction_count(sender, "pending"),
                    "chainId": w3.eth.chain_id,
                    "gasPrice": int(w3.eth.gas_price * 1.1)
                })
                signed = Account.from_key(key).sign_transaction(tx)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                
                balance = usdc_contract.functions.balanceOf(recipient).call()
                logger.info(f"Minted {acc['amount_usdc']} USDC to {acc.get('alias', recipient)} ({recipient}). Current balance: {balance / 1e6} USDC")
                results.append({
                    "alias": acc.get("alias", ""),
                    "address": recipient,
                    "minted_usdc": acc["amount_usdc"],
                    "balance_usdc": balance / 1e6,
                    "tx_hash": tx_hash.hex()
                })
            else:
                logger.warning("Contract does not have a public 'mint' function.")
                break
        except Exception as e:
            logger.error(f"Failed to mint to {recipient}: {e}")

    return results

if __name__ == "__main__":
    mint_usdc_to_accounts()
