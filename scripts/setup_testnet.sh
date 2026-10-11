#!/usr/bin/env bash
# DarkBatch EVM Settlement Testnet Setup Script (Bash)
# Configures environment, verifies tooling, launches local EVM node (if required),
# compiles & deploys DarkBatchEscrow & MockUSDC, and mints test liquidity.

set -euo pipefail

echo "=========================================================="
echo "     DarkBatch USDC Escrow & EVM Testnet Setup            "
echo "=========================================================="

# 1. Tool Verification
echo -e "\n[1/5] Verifying toolchain..."
command -v python3 >/dev/null 2>&1 && PYTHON="python3" || PYTHON="python"
$PYTHON --version
command -v node >/dev/null 2>&1 && node --version || echo "Node.js not in PATH"
command -v npm >/dev/null 2>&1 && npm --version || echo "npm not in PATH"

# Ensure solc 0.8.20 is installed via solcx
$PYTHON -c "import solcx; solcx.install_solc('0.8.20')"

# 2. Python Dependencies Check & Installation
echo -e "\n[2/5] Installing/verifying Python dependencies..."
$PYTHON -m pip install --quiet web3 aiohttp grpcio py-solc-x eth-account eth-tester[py-evm]

# 3. Local EVM Node Management
echo -e "\n[3/5] Checking EVM RPC endpoint..."
RPC_URL="${EVM_RPC_URL:-http://127.0.0.1:8545}"

IS_UP=0
if curl -s -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | grep -q "result"; then
    IS_UP=1
    echo "  [OK] Existing EVM node detected at $RPC_URL"
fi

if [ "$IS_UP" -eq 0 ]; then
    echo "  [INFO] No active node found at $RPC_URL. Spawning local EVM test node..."
    if command -v anvil >/dev/null 2>&1; then
        anvil --port 8545 --chain-id 31337 >/dev/null 2>&1 &
    elif command -v npx >/dev/null 2>&1 && [ -f "hardhat.config.js" ]; then
        npx hardhat node >/dev/null 2>&1 &
    else
        $PYTHON scripts/local_evm_node.py --port 8545 >/dev/null 2>&1 &
    fi

    # Wait for node to start
    ATTEMPTS=0
    while [ "$IS_UP" -eq 0 ] && [ "$ATTEMPTS" -lt 20 ]; do
        sleep 1
        ATTEMPTS=$((ATTEMPTS + 1))
        if curl -s -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | grep -q "result"; then
            IS_UP=1
            echo "  [OK] Local EVM node online at $RPC_URL"
        fi
    done

    if [ "$IS_UP" -eq 0 ]; then
        echo "Failed to start local EVM node."
        exit 1
    fi
fi

export EVM_RPC_URL="$RPC_URL"

# 4. Deploy DarkBatchEscrow & MockUSDC
echo -e "\n[4/5] Deploying DarkBatchEscrow smart contract..."
$PYTHON scripts/deploy_escrow.py

# 5. Mint Test USDC Liquidity
echo -e "\n[5/5] Minting test USDC tokens to DarkBatch participants..."
$PYTHON scripts/mint_test_tokens.py

echo -e "\n=========================================================="
echo "            DARKBATCH TESTNET SETUP COMPLETE              "
echo "=========================================================="
if [ -f "contracts/deployed.json" ]; then
    $PYTHON -c "import json; d=json.load(open('contracts/deployed.json')); print(f\"RPC URL: {d['network']['rpc_url']}\nChain ID: {d['network']['chain_id']}\nDeployer: {d['deployer']}\nEscrow Contract: {d['escrow']['address']}\nUSDC Token: {d['usdc']['address']}\nOracle: {d['escrow']['oracle']}\")"
fi
echo "=========================================================="
