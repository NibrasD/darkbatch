# DarkBatch — Technical Committee Submission Brief

## One-line summary

DarkBatch is a research prototype for privacy-oriented, uniform-price batch trading of shielded ZEC, paired with an on-chain USDC payout escrow and a confirmation-gated Zcash-to-EVM settlement workflow.

## Problem

Peer-to-peer swaps and continuous-order execution expose traders to price timing, fragmented liquidity, and coordination overhead. DarkBatch explores batching compatible orders into an epoch, selecting one clearing price, and preparing the shielded ZEC leg as a valid Zcash V6 transaction rather than treating local balance changes or transaction-shaped data as settlement.

## Proposed approach

DarkBatch separates matching from custody-sensitive transaction construction and from cross-chain settlement:

1. **Match a batch.** The FBA solver evaluates the intents in an epoch and calculates a uniform clearing price. Marginal fills use deterministic integer-zatoshi allocation; the plan must balance buyer and seller fills.
2. **Prepare with actual wallet state.** A local Zebra Testnet scanner maintains Ironwood notes and Merkle witnesses. A private inventory exporter checks wallet-derived addresses, wallet tip/root consistency, and witness freshness. Sensitive notes and key material stay local.
3. **Build a Zcash transaction.** The official-library Rust/PCZT path constructs participant spends and recipient/change outputs, gathers signatures over redacted PCZT contributions, performs proof generation, and extracts raw V6 bytes. The coordinator does not build a spend from simulated notes.
4. **Gate the USDC leg.** The configured escrow must already hold the exact USDC amounts for the matching plan. Before ZEC broadcast, the coordinator compares the plan/payout commitments and also requires the canonical `BatchFullyFunded` event to have at least two EVM confirmations.
5. **Confirm and release.** The local oracle verifies the ZEC transaction and confirmation depth against Zebra and the coordinator's epoch/batch association, attests that transaction to the escrow, releases USDC, then asks the coordinator to finalize only after the matching release receipt is verified.
6. **Recover without duplicate payment transactions.** If an EVM receipt is delayed, the local workflow persists the submitted hash and polls that same transaction on retry instead of intentionally broadcasting a replacement. Uncertain states remain pending, not settled.

## What distinguishes this prototype

- It distinguishes local simulation, proof generation, broadcast acceptance, block confirmation, and cross-asset completion.
- The legacy assembler is blocked from live broadcast; the raw submitter accepts the transaction extracted by the official-library PCZT path.
- Wallet note openings, viewing keys, witnesses, PCZTs, and spending keys are treated as local secrets, not coordinator payloads.
- USDC payouts are committed to exact recipients and amounts in a deployed escrow contract instead of represented by an internal database balance.
- The local oracle is deliberately explicit and configurable. It is a trust assumption, not a cryptographic light client for Zcash consensus.

## Architecture at a glance

~~~text
FBA intents
    |
Uniform-price clearing plan
    |
Private local wallet inventory (real Ironwood notes + witnesses)
    |
Official Rust PCZT -> participant signing -> Halo 2 proof -> V6 extraction
    |
Zebra Testnet broadcast and confirmation
    |
Oracle checks TXID + block + epoch + USDC plan commitment
    |
EVM attestation -> USDC escrow release
    |
Coordinator verifies release receipt -> CLEARED
~~~

## Review and reproduction

### Local matching demo

Install the project dependencies and start the API:

~~~bash
python -m pip install -r requirements.txt
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
~~~

In a second terminal:

~~~bash
python darkbatch/cli/darkbatch_cli.py epoch seed
python darkbatch/cli/darkbatch_cli.py epoch status
python darkbatch/cli/darkbatch_cli.py epoch clear
~~~

Open the local dashboard at http://127.0.0.1:8000. This demonstrates the matching prototype and fail-closed API behaviour; it does **not** make live ZEC or USDC transfers.

### Component validation

~~~bash
cargo build --release --manifest-path darkbatch_crypto/Cargo.toml
cargo test --release --manifest-path darkbatch_crypto/Cargo.toml
python -m compileall -q darkbatch
python -m pytest darkbatch/tests/ -v
forge test --root contracts -vv
~~~

The project includes regression tests for matching, local wallet inventory validation, PCZT orchestration, escrow encoding and oracle checks. Current GitHub Actions attempts on the integrated branch have not executed these commands: their jobs were marked failed with zero steps and no assigned runner. Therefore the latest integrated branch does not yet have a verified passing CI result.

### Live Testnet evaluation

Follow [IRONWOOD_LOCAL_WALLET_WORKFLOW.md](IRONWOOD_LOCAL_WALLET_WORKFLOW.md). A meaningful end-to-end evaluation requires all of the following: a synced Zebra Testnet node, funded spendable testnet notes with current witnesses, locally protected participant spending-key files, a deployed EVM test escrow, a funded USDC batch whose commitments match the exact FBA plan, and the oracle key configured in that escrow. The opt-in **--settle-usdc** command submits irreversible Testnet transactions and must only be used after preflight.

For a committee evidence bundle, capture sanitized outputs proving each stage independently:

- the matching plan identifier and committed USDC payout-plan hash;
- the extracted Zcash transaction ID and proof report;
- the Zebra-reported block hash and required confirmations;
- the EVM attestation transaction hash and successful receipt;
- the EVM USDC release transaction hash and successful receipt;
- the coordinator response showing **CLEARED** for the same epoch, ZEC TXID, escrow batch and release TXID.

Do not include API tokens, EVM private keys, spending keys, wallet inventory, note openings, Merkle witnesses, or private PCZT artifacts in a public submission. A screenshot of the dashboard or an unconfirmed transaction is not sufficient evidence of cross-chain completion.

## Important limitations

- **Live end-to-end evidence is still outstanding.** The full workflow exists in code but has not yet been demonstrated with a funded real Testnet wallet and a deployed/funded EVM escrow in this development session.
- **Not an audited protocol.** The FBA design, PCZT participant coordination, wallet implementation and contract require independent review before any mainnet use.
- **Oracle trust.** The configured oracle can attest to Zcash observations; the EVM contract does not independently verify Zebra consensus or shielded transaction validity.
- **Trusted local workflow.** The current local agent orchestrates private PCZT files and reads local key files. The participant-redaction flow is not a claim of a fully decentralized, independently audited multi-party signing service.
- **Refund tooling gap.** The contract restricts the refund transition to the configured oracle, but the bundled oracle CLI does not yet provide the expiry/refund-attestation path. Expired batches are not automatically refundable through the current tooling.
- **No mainnet funds.** Do not use this prototype to custody or exchange real assets.

## Source and workflow

- Repository: https://github.com/NibrasD/darkbatch
- Local PCZT implementation: [LOCAL_PCZT_SETTLEMENT.md](LOCAL_PCZT_SETTLEMENT.md)
- Wallet scan and settlement workflow: [IRONWOOD_LOCAL_WALLET_WORKFLOW.md](IRONWOOD_LOCAL_WALLET_WORKFLOW.md)
