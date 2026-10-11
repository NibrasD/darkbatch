# DarkBatch configuration reference

This is a reference for the local matching demo, Zebra Testnet wallet tooling, and optional USDC escrow operations. The repository does not automatically load .env files. Set environment variables in the shell/process that runs each command. Never commit real private keys, settlement tokens, RPC passwords, wallet inventories, notes, Merkle witnesses, or PCZT files.

## Local coordinator and Zcash Testnet

| Variable | Purpose |
|---|---|
| `DARKBATCH_API_BASE` | Coordinator URL used by the local PCZT agent. Defaults to `http://127.0.0.1:8000`. Remote coordinator URLs must use HTTPS. |
| `DARKBATCH_SETTLEMENT_TOKEN` | Shared token protecting local settlement routes. Configure it only in the coordinator process and trusted local agent. |
| `ZCASH_TESTNET_RPC_URL` | RPC endpoint of a synced Zebra Testnet node. The live path checks that the endpoint identifies as Zebra. |
| `ZCASH_TESTNET_RPC_USER`, `ZCASH_TESTNET_RPC_PASS` | Optional RPC credentials if required by the local node. |
| `DARKBATCH_CRYPTO_BIN` | Optional path to the built Rust CLI. The default is `darkbatch_crypto/target/release/darkbatch_crypto`. |
| `DARKBATCH_SOLVER_FEE_RECEIVER_RAW_HEX` | Exact 43-byte Ironwood receiver used when the plan charges a non-zero ZEC solver fee. |
| `DARKBATCH_ALLOW_SIMULATION` | Keep `false` for real settlement paths. Simulation is not settlement. |

## USDC escrow and EVM RPC

| Variable | Purpose |
|---|---|
| `DARKBATCH_QUOTE_RPC_URL` | JSON-RPC endpoint for the EVM network where the escrow is deployed. |
| `DARKBATCH_QUOTE_CHAIN_ID` | Exact EVM chain ID checked against the connected RPC. |
| `DARKBATCH_QUOTE_DEPLOYMENT_BLOCK` | Confirmed block number containing the canonical `DarkBatchQuoteEscrow` deployment. The coordinator starts its `BatchFullyFunded` event scan here. |
| `DARKBATCH_USDC_TOKEN_ADDRESS` | Canonical six-decimal USDC token contract on that EVM network. |
| `DARKBATCH_USDC_ESCROW_ADDRESS` | Deployed contract compiled from `contracts/src/DarkBatchQuoteEscrow.sol`. |

The operator/buyer/oracle scripts use private keys from the local environment:

| Variable | Purpose |
|---|---|
| `DARKBATCH_QUOTE_COORDINATOR_PRIVATE_KEY` | Operator account authorized to call `openBatch`. |
| `DARKBATCH_BUYER_PRIVATE_KEY` | Buyer account depositing its USDC obligation. |
| `DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY` | Oracle account configured in the deployed escrow. This is a high-trust secret. |

## Confirmation requirements

The implementation requires at least **two ZEC confirmations** before USDC attestation/release and at least **two EVM confirmations** for the funded-batch event and release receipt. Defaults are:

- `DARKBATCH_MINIMUM_ZEC_CONFIRMATIONS=2`
- `DARKBATCH_MINIMUM_FINALIZATION_CONFIRMATIONS=2`
- `DARKBATCH_QUOTE_MIN_CONFIRMATIONS=2`

Values below two are rejected. EVM confirmation counts do not replace checking the exact escrow event, batch ID, plan hash, and payout hash.

## Private work artifacts

- `DARKBATCH_USDC_BATCH_ID`: 32-byte batch ID for operator workflows.
- `DARKBATCH_USDC_BATCH_DEADLINE_SECONDS`: registration helper duration, between 30 minutes and seven days.
- `DARKBATCH_EPOCH_ID`, `DARKBATCH_ZEC_TXID`: epoch and confirmed TXID used by the explicit operator release script.
- `DARKBATCH_RELEASE_STATE_PATH`: optional release-recovery state path. Keep it private; by default it is stored under ignored `private-work/`.

See [IRONWOOD_LOCAL_WALLET_WORKFLOW.md](IRONWOOD_LOCAL_WALLET_WORKFLOW.md) for scanning real notes, creating the private wallet inventory, building/proving the PCZT, broadcasting to Zebra, and optionally settling USDC.

## Important limitation

The code and tests are not an audited cross-chain protocol. No funded end-to-end ZEC+USDC Testnet execution has been evidenced in this development session. The bundled oracle implements confirmation and release; automated expiry/refund attestation tooling remains incomplete even though the contract gates the refund transition behind the configured oracle. Do not use real funds or treat this as a production DEX.
