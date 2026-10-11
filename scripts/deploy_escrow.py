#!/usr/bin/env python3
"""
DarkBatch USDC Escrow Deployment Script
Compiles DarkBatchEscrow and MockUSDC contracts using solcx,
deploys them to an EVM network (Sepolia, Anvil, Hardhat, etc.),
and persists addresses & ABIs to contracts/deployed.json.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import solcx
from web3 import Web3
from web3.exceptions import TransactionNotFound, TimeExhausted
from eth_account import Account

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("darkbatch.deploy")

ROOT_DIR = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = ROOT_DIR / "contracts"
DEPLOYED_JSON_PATH = CONTRACTS_DIR / "deployed.json"
SOLC_VERSION = "0.8.20"

def ensure_solc():
    """Ensures solc 0.8.20 is installed and active."""
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if SOLC_VERSION not in installed:
        logger.info(f"Installing Solidity compiler version {SOLC_VERSION}...")
        solcx.install_solc(SOLC_VERSION)
    solcx.set_solc_version(SOLC_VERSION)
    logger.info(f"Using solc version {SOLC_VERSION}")

def compile_contracts() -> Dict[str, Any]:
    """
    Compiles DarkBatchEscrow.sol and MockUSDC.sol.
    Returns dictionary of contract artifacts.
    """
    ensure_solc()
    escrow_file = CONTRACTS_DIR / "DarkBatchEscrow.sol"
    mock_usdc_file = CONTRACTS_DIR / "MockUSDC.sol"

    if not escrow_file.exists():
        raise FileNotFoundError(f"Contract file not found: {escrow_file}")

    files_to_compile = [str(escrow_file)]
    if mock_usdc_file.exists():
        files_to_compile.append(str(mock_usdc_file))

    logger.info(f"Compiling Solidity files: {files_to_compile}")
    compiled = solcx.compile_files(
        files_to_compile,
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        optimize=True,
        optimize_runs=200
    )
    return compiled

def get_web3_provider(rpc_url: Optional[str] = None) -> Web3:
    """Connects to the EVM RPC endpoint with timeout configuration."""
    url = rpc_url or os.getenv("EVM_RPC_URL", "http://127.0.0.1:8545")
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise ConnectionError(f"Could not connect to EVM RPC at {url}")
    logger.info(f"Connected to EVM node at {url} (Chain ID: {w3.eth.chain_id})")
    return w3

def send_transaction_with_retries(
    w3: Web3,
    tx_params: Dict[str, Any],
    private_key: str,
    max_retries: int = 3,
    timeout: int = 120
) -> Dict[str, Any]:
    """Signs, broadcasts, and awaits confirmation for a transaction with retries."""
    account = Account.from_key(private_key)
    sender = account.address

    for attempt in range(1, max_retries + 1):
        try:
            nonce = w3.eth.get_transaction_count(sender, "pending")
            tx_params["nonce"] = nonce
            tx_params["from"] = sender

            # Populate gas parameters
            if "gas" not in tx_params:
                try:
                    estimated = w3.eth.estimate_gas(tx_params)
                    tx_params["gas"] = int(estimated * 1.25)
                except Exception as e:
                    logger.warning(f"Gas estimation failed: {e}. Using default gas limit 3,000,000.")
                    tx_params["gas"] = 3_000_000

            # EIP-1559 or legacy fee handling
            try:
                latest_block = w3.eth.get_block("latest")
                if "baseFeePerGas" in latest_block and latest_block["baseFeePerGas"] is not None:
                    base_fee = latest_block["baseFeePerGas"]
                    priority_fee = w3.eth.max_priority_fee
                    tx_params["maxPriorityFeePerGas"] = priority_fee
                    tx_params["maxFeePerGas"] = int(base_fee * 1.5) + priority_fee
                    tx_params.pop("gasPrice", None)
                else:
                    tx_params["gasPrice"] = int(w3.eth.gas_price * 1.1)
            except Exception:
                tx_params["gasPrice"] = w3.eth.gas_price

            signed_tx = account.sign_transaction(tx_params)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Broadcast tx {tx_hash.hex()} (attempt {attempt}/{max_retries})")

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            if receipt.get("status") == 1:
                return receipt
            else:
                raise RuntimeError(f"Transaction failed with status 0: {tx_hash.hex()}")

        except (TimeExhausted, TransactionNotFound) as te:
            logger.warning(f"Timeout on attempt {attempt}: {te}")
            if attempt == max_retries:
                raise
            time.sleep(2)
        except Exception as ex:
            logger.warning(f"Error on attempt {attempt}: {ex}")
            if attempt == max_retries:
                raise
            time.sleep(2)

def deploy_contract(
    w3: Web3,
    abi: list,
    bytecode: str,
    deployer_key: str,
    constructor_args: list = None
) -> Tuple[str, Any]:
    """Deploys a contract given its ABI, bytecode, and constructor args."""
    constructor_args = constructor_args or []
    account = Account.from_key(deployer_key)
    contract_factory = w3.eth.contract(abi=abi, bytecode=bytecode)

    construct_txn = contract_factory.constructor(*constructor_args).build_transaction({
        "chainId": w3.eth.chain_id,
        "from": account.address
    })

    receipt = send_transaction_with_retries(w3, construct_txn, deployer_key)
    contract_address = receipt["contractAddress"]
    deployed_instance = w3.eth.contract(address=contract_address, abi=abi)
    return contract_address, deployed_instance

def run_deployment(
    rpc_url: Optional[str] = None,
    deployer_key: Optional[str] = None,
    usdc_address: Optional[str] = None,
    oracle_address: Optional[str] = None
) -> Dict[str, Any]:
    """Main deployment pipeline."""
    w3 = get_web3_provider(rpc_url)
    
    # 1. Resolve Deployer Key
    key = deployer_key or os.getenv("DEPLOYER_PRIVATE_KEY")
    if not key:
        # Check if local node has unlocked test accounts
        if len(w3.eth.accounts) > 0:
            # Common Anvil / Hardhat Account #0 default private key
            logger.info("DEPLOYER_PRIVATE_KEY not set. Using local development test key.")
            key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        else:
            raise ValueError("DEPLOYER_PRIVATE_KEY environment variable is required")

    deployer = Account.from_key(key).address
    balance_eth = w3.from_wei(w3.eth.get_balance(deployer), "ether")
    logger.info(f"Deployer Address: {deployer} (Balance: {balance_eth} ETH)")

    # 2. Compile Contracts
    compiled = compile_contracts()

    # Locate escrow artifact
    escrow_key = next((k for k in compiled.keys() if k.endswith(":DarkBatchEscrow")), None)
    if not escrow_key:
        raise RuntimeError("Failed to compile DarkBatchEscrow")

    escrow_abi = compiled[escrow_key]["abi"]
    escrow_bin = compiled[escrow_key]["bin"]

    # 3. Resolve / Deploy USDC
    active_usdc_address = usdc_address or os.getenv("USDC_ADDRESS")
    usdc_abi = []
    mock_usdc_key = next((k for k in compiled.keys() if k.endswith(":MockUSDC")), None)

    if mock_usdc_key:
        usdc_abi = compiled[mock_usdc_key]["abi"]

    if not active_usdc_address:
        if not mock_usdc_key:
            raise RuntimeError("USDC_ADDRESS not provided and MockUSDC contract not found.")
        logger.info("USDC_ADDRESS not set. Deploying MockUSDC token...")
        mock_bin = compiled[mock_usdc_key]["bin"]
        active_usdc_address, usdc_contract = deploy_contract(
            w3, usdc_abi, mock_bin, key, []
        )
        logger.info(f"MockUSDC successfully deployed at: {active_usdc_address}")

        # Mint initial test USDC tokens to deployer (e.g. 100,000 USDC = 100,000 * 10^6)
        logger.info(f"Minting initial 100,000 USDC to deployer {deployer}...")
        mint_txn = usdc_contract.functions.mint(deployer, 100_000 * 10**6).build_transaction({
            "chainId": w3.eth.chain_id,
            "from": deployer
        })
        send_transaction_with_retries(w3, mint_txn, key)
        logger.info("Minted 100,000 USDC successfully.")
    else:
        logger.info(f"Using existing USDC address: {active_usdc_address}")

    # 4. Resolve Settlement Oracle
    active_oracle = oracle_address or os.getenv("ORACLE_ADDRESS") or deployer
    logger.info(f"Configuring Settlement Oracle: {active_oracle}")

    # 5. Deploy DarkBatchEscrow
    logger.info(f"Deploying DarkBatchEscrow(USDC={active_usdc_address}, Oracle={active_oracle})...")
    escrow_address, escrow_contract = deploy_contract(
        w3,
        escrow_abi,
        escrow_bin,
        key,
        [Web3.to_checksum_address(active_usdc_address), Web3.to_checksum_address(active_oracle)]
    )
    logger.info(f"DarkBatchEscrow successfully deployed at: {escrow_address}")

    # 6. Save deployed info to contracts/deployed.json
    deployment_record = {
        "network": {
            "chain_id": w3.eth.chain_id,
            "rpc_url": w3.provider.endpoint_uri if hasattr(w3.provider, "endpoint_uri") else "custom"
        },
        "deployer": deployer,
        "escrow": {
            "address": escrow_address,
            "oracle": active_oracle,
            "abi": escrow_abi
        },
        "usdc": {
            "address": active_usdc_address,
            "abi": usdc_abi
        },
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    DEPLOYED_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DEPLOYED_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(deployment_record, f, indent=2)

    logger.info(f"Deployment record written to {DEPLOYED_JSON_PATH}")
    return deployment_record

if __name__ == "__main__":
    try:
        record = run_deployment()
        print("\n=== DEPLOYMENT SUMMARY ===")
        print(f"Chain ID:       {record['network']['chain_id']}")
        print(f"Deployer:       {record['deployer']}")
        print(f"USDC Address:   {record['usdc']['address']}")
        print(f"Escrow Address: {record['escrow']['address']}")
        print(f"Escrow Oracle:  {record['escrow']['oracle']}")
        print(f"Record File:    {DEPLOYED_JSON_PATH}")
    except Exception as e:
        logger.error(f"Deployment failed: {e}", exc_info=True)
        sys.exit(1)
