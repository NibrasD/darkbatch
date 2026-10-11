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

No contract is deployed by the repository changes. The coordinator can set `DARKBATCH_QUOTE_MIN_CONFIRMATIONS` (default `2`) to require additional EVM block confirmations for USDC release receipts. The finalization route requires at least two Zebra confirmations by default; operators may increase but cannot lower that floor through `DARKBATCH_MINIMUM_FINALIZATION_CONFIRMATIONS`. Before any value is used, choose a target EVM network; verify its canonical USDC token address and six-decimal amount convention; deploy the contract with distinct operator and oracle accounts; fund only test tokens first; and independently test refund and payout paths. Configure the coordinator with `DARKBATCH_QUOTE_RPC_URL`, `DARKBATCH_QUOTE_CHAIN_ID`, `DARKBATCH_QUOTE_DEPLOYMENT_BLOCK` (the deployment transaction's confirmed block number), `DARKBATCH_USDC_TOKEN_ADDRESS`, and `DARKBATCH_USDC_ESCROW_ADDRESS`. The coordinator refuses ZEC broadcast unless it finds the matching `BatchFullyFunded(batchId, planHash)` event and that event has at least two EVM confirmations. Set the deployment block accurately so the log query does not scan from genesis or skip the event.

The oracle is a major trust boundary: the EVM contract cannot prove that a shielded Zcash transaction is confirmed or unconfirmed. The bundled Python oracle implements the confirmation-and-release path; it does **not** currently provide an automated expiry/refund attestation command. The contract refund transition is restricted to the configured oracle, so expired batches must not be described as automatically refundable by this repository until that path is implemented and tested. There is currently no deployed oracle or end-to-end key management in this repository. The contract and the whole cross-chain mechanism have not been audited and must not be used with real funds.

The coordinator does not sign, deposit, release, or refund USDC. Contract transactions require the operator, buyers, oracle, or a caller to submit them directly on the selected EVM network.

## Local ZEC confirmation oracle

After the API has associated an exact, real ZEC TXID with the epoch, this tool independently checks Zebra's Testnet identity, the TXID's block/confirmation count, the coordinator's epoch association, and the escrow's plan/payout hashes. Its default is read-only:

```powershell
$env:DARKBATCH_SETTLEMENT_TOKEN = "<local API token>"
python -m darkbatch.settlement.quote_oracle --api-base http://127.0.0.1:8000 --epoch-id 12 --quote-batch-id 0x<64-hex-batch-id> --zec-txid <64-hex-zcash-txid> --plan-json .\private\epoch-12\fba-plan.json
```

To let the local script sign and broadcast the oracle attestation, configure `DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY` **in the trusted local shell only** and add `--submit`. Adding `--release-usdc` explicitly sends a second EVM call to release seller payouts after the oracle attestation is mined. Neither key nor PCZT/note openings are sent to the coordinator. Do not run this against real USDC before audit, and do not trust an oracle key with more funds than the escrow's narrowly scoped role requires.

The oracle requires an associated API record and a synced Testnet Zebra RPC; it refuses to attest solely from a caller-provided TXID. This code has not been run against an actual Zebra node or EVM network in this environment.


## Operator scripts

The scripts under `scripts/` target the canonical contract compiled from `contracts/src/DarkBatchQuoteEscrow.sol`. They share its exact ABI, including the eleventh `escrowDataHash` return value. The buyer deposit script looks up the buyer row through `buyerAt(batchId,index)`; do not deploy an older contract copy with different methods.

Install the Node dependencies:

~~~bash
cd scripts
npm install
~~~

The release helper requires at least two Zebra confirmations and at least two EVM confirmations by default. It saves signed EVM transaction hashes before broadcasting and resumes polling those hashes instead of automatically creating replacement transactions. Keep its state file private. The helper still depends on the configured oracle key and trusted Zebra RPC; it does not remove the oracle trust assumption.
