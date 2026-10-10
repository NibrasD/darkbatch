# DarkBatch Quote Escrow (USDC)

This contract is an initial, unaudited escrow implementation for a DarkBatch FBA quote leg. It assumes the configured ERC-20 token is the intended USDC deployment with six decimals; amounts passed by the coordinator are micro-USDC integers.

## State flow

`OPEN -> FUNDED -> ZEC_CONFIRMED -> RELEASED`

The operator opens a batch with a fixed plan hash, sorted buyer deposit rows, sorted seller payout rows, and deadline. Every buyer line must fund its exact amount. Only when every row is funded does the batch become `FUNDED`. Only the configured oracle may attest a non-zero ZEC transaction ID and block hash, after independently checking Zebra; any account may then call `releaseBatch`.

An unconfirmed batch can become `REFUNDABLE` only after its deadline and only through the oracle. The oracle must verify that the ZEC leg is not confirmed and cannot still validly confirm before attesting this. Paid buyers can claim only their own deposits. A successful refund does not alter another buyer's entitlement.

The contract exposes eleven static ABI words via `getBatchStatus(bytes32)`. Word 11 is `escrowDataHash = keccak256(abi.encode(buyerAddresses, buyerAmounts, sellerAddresses, sellerAmounts))`. The coordinator compares it with the exact plan's payout arrays as well as comparing the plan hash and totals. When finalizing, the coordinator also requires the confirmed escrow batch to reference the exact ZEC TXID and block hash stored for the epoch, and verifies an EVM receipt containing the matching `BatchReleased(batchId, zecTxid)` event plus the configured minimum number of EVM confirmations.

## Prepare the operator's openBatch call

The helper produces and checks the exact, sorted deposit/payout arrays plus the ABI calldata; it does not sign or broadcast anything.

```powershell
$deadline = [DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()
python -m darkbatch.settlement.prepare_quote_escrow_batch --plan-json .\private\quote-plan.json --batch-id 0x<64-hex-batch-id> --deadline $deadline --output .\private\escrow-open.json
```

Review the complete manifest, especially every buyer/seller EVM address, amount, token, contract address and deadline, before using `calldata_hex` with a secure wallet/signer to call `openBatch`. This helper has no private key and cannot submit an EVM transaction.

## Build and test

Install Foundry, then from the repository root run:

```bash
forge test --root contracts -vv
```

## Deployment prerequisites

No contract is deployed by the repository changes. The coordinator can set `DARKBATCH_QUOTE_MIN_CONFIRMATIONS` (default `1`) to require additional EVM block confirmations for USDC release receipts. Before any value is used, choose a target EVM network; verify its canonical USDC token address and six-decimal amount convention; deploy the contract with distinct operator and oracle accounts; fund only test tokens first; and independently test refund and payout paths. Configure the coordinator with `DARKBATCH_QUOTE_RPC_URL`, `DARKBATCH_QUOTE_CHAIN_ID`, `DARKBATCH_USDC_TOKEN_ADDRESS`, and `DARKBATCH_USDC_ESCROW_ADDRESS`.

The oracle is a major trust boundary: the EVM contract cannot prove that a shielded Zcash transaction is confirmed or unconfirmed. The oracle service must independently query a trusted, synchronized Zebra node and publish confirmation / expiry attestations. There is currently no deployed oracle or end-to-end key management in this repository. The contract and the whole cross-chain mechanism have not been audited and must not be used with real funds.

The coordinator does not sign, deposit, release, or refund USDC. Contract transactions require the operator, buyers, oracle, or a caller to submit them directly on the selected EVM network.
