# DarkBatch EVM Settlement Testnet Setup Script (PowerShell)
# Configures environment, verifies tooling, launches local EVM node (if required),
# compiles & deploys DarkBatchEscrow & MockUSDC, and mints test liquidity.

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     DarkBatch USDC Escrow & EVM Testnet Setup            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Tool Verification
Write-Host "`n[1/5] Verifying toolchain..." -ForegroundColor Yellow

# Python Check
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  [OK] Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "Python 3 is required but not found in PATH."
    exit 1
}

# Node.js & npm Check
try {
    $nodeVersion = node --version 2>&1
    $npmVersion = npm --version 2>&1
    Write-Host "  [OK] Node.js: $nodeVersion" -ForegroundColor Green
    Write-Host "  [OK] npm: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Node.js/npm not detected in standard path." -ForegroundColor Yellow
}

# Solidity Compiler (solc) Check
try {
    python -c "import solcx; solcx.install_solc('0.8.20'); print('  [OK] solc version:', solcx.get_installed_solc_versions()[0])"
    Write-Host "  [OK] Solidity compiler (0.8.20) ready." -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Installing solc 0.8.20..." -ForegroundColor Cyan
    python -c "import solcx; solcx.install_solc('0.8.20')"
}

# 2. Python Dependencies Check & Installation
Write-Host "`n[2/5] Installing/verifying Python dependencies..." -ForegroundColor Yellow
python -m pip install --quiet web3 aiohttp grpcio py-solc-x eth-account eth-tester[py-evm]
Write-Host "  [OK] Python dependencies verified." -ForegroundColor Green

# 3. Local EVM Node Management
Write-Host "`n[3/5] Checking EVM RPC endpoint..." -ForegroundColor Yellow

$rpcUrl = $env:EVM_RPC_URL
if (-not $rpcUrl) {
    $rpcUrl = "http://127.0.0.1:8545"
}

# Test if RPC is already responding
$isRpcUp = $false
try {
    $response = Invoke-RestMethod -Uri $rpcUrl -Method Post -Body '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' -ContentType "application/json" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($response.result -ne $null) {
        $isRpcUp = $true
        Write-Host "  [OK] Existing EVM node detected at $rpcUrl" -ForegroundColor Green
    }
} catch {
    $isRpcUp = $false
}

if (-not $isRpcUp) {
    Write-Host "  [INFO] No active node found at $rpcUrl. Spawning local EVM test node..." -ForegroundColor Cyan
    
    # Check for Anvil
    $anvilCmd = Get-Command anvil -ErrorAction SilentlyContinue
    if ($anvilCmd) {
        Write-Host "  [INFO] Starting Anvil node on port 8545..." -ForegroundColor Cyan
        Start-Process -FilePath "anvil" -ArgumentList "--port", "8545", "--chain-id", "31337" -WindowStyle Hidden
    } else {
        # Check for Hardhat
        $npxCmd = Get-Command npx -ErrorAction SilentlyContinue
        $hardhatConfig = Test-Path "hardhat.config.js"
        if ($npxCmd -and $hardhatConfig) {
            Write-Host "  [INFO] Starting Hardhat node..." -ForegroundColor Cyan
            Start-Process -FilePath "npx" -ArgumentList "hardhat", "node" -WindowStyle Hidden
        } else {
            # Start standalone high-fidelity Python EVM node
            Write-Host "  [INFO] Starting DarkBatch local EVM server on port 8545..." -ForegroundColor Cyan
            Start-Process -FilePath "python" -ArgumentList "scripts/local_evm_node.py", "--port", "8545" -WindowStyle Hidden
        }
    }

    # Await node readiness
    $attempts = 0
    while (-not $isRpcUp -and $attempts -lt 20) {
        Start-Sleep -Seconds 1
        $attempts++
        try {
            $resp = Invoke-RestMethod -Uri $rpcUrl -Method Post -Body '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' -ContentType "application/json" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($resp.result -ne $null) {
                $isRpcUp = $true
                Write-Host "  [OK] Local EVM node online at $rpcUrl (ready in ${attempts}s)" -ForegroundColor Green
            }
        } catch {
            # continue polling
        }
    }

    if (-not $isRpcUp) {
        Write-Error "Failed to start or connect to local EVM node at $rpcUrl within timeout."
        exit 1
    }
}

$env:EVM_RPC_URL = $rpcUrl

# 4. Deploy DarkBatchEscrow & MockUSDC
Write-Host "`n[4/5] Deploying DarkBatchEscrow smart contract..." -ForegroundColor Yellow
python scripts/deploy_escrow.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "Contract deployment failed."
    exit 1
}

# 5. Mint Test USDC Liquidity
Write-Host "`n[5/5] Minting test USDC tokens to DarkBatch participants..." -ForegroundColor Yellow
python scripts/mint_test_tokens.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "USDC token minting failed."
    exit 1
}

# Print Configuration Summary
$deployedJsonPath = "contracts/deployed.json"
if (Test-Path $deployedJsonPath) {
    $deployed = Get-Content $deployedJsonPath | ConvertFrom-Json
    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "            DARKBATCH TESTNET SETUP COMPLETE              " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host "  RPC URL:         $($deployed.network.rpc_url)" -ForegroundColor White
    Write-Host "  Chain ID:        $($deployed.network.chain_id)" -ForegroundColor White
    Write-Host "  Deployer:        $($deployed.deployer)" -ForegroundColor White
    Write-Host "  Escrow Contract: $($deployed.escrow.address)" -ForegroundColor Yellow
    Write-Host "  USDC Token:      $($deployed.usdc.address)" -ForegroundColor Yellow
    Write-Host "  Oracle Address:  $($deployed.escrow.oracle)" -ForegroundColor White
    Write-Host "  Deployed Record: contracts/deployed.json" -ForegroundColor White
    Write-Host "==========================================================`n" -ForegroundColor Green
}
