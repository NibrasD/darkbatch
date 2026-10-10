# DarkBatch

**Privacy-preserving uniform-price batch trading for shielded Zcash, with a USDC quote-asset escrow.**

DarkBatch explores a frequent batch auction (FBA) where orders are matched off-chain in discrete epochs and ZEC settlement is constructed with Zcash's official Rust/PCZT tooling. A separate EVM escrow holds USDC payouts and releases them only after a local oracle verifies the associated ZEC transaction on Zebra Testnet.

> **Project status: research prototype.** The repository now contains the local Ironwood wallet scanner, real-note inventory exporter, official-library PCZT build/sign/prove/extract path, Zebra broadcast/confirmation tracking, USDC escrow checks, and opt-in oracle/release/recovery workflow. The complete cross-chain path has **not yet been demonstrated end-to-end on a funded Testnet wallet and deployed EVM escrow**. Do not present a local test, simulated receipt, successful broadcast, or code path as proof of a confirmed cross-chain settlement. Do not use mainnet funds.

## What the project does

1. **Batch matching.** Collects sealed intents, finds a uniform clearing price, and uses deterministic integer-zatoshi allocation for marginal pro-rata fills.
2. **Private local spend preparation.** A locally run Zebra Testnet scanner tracks actual Ironwood notes and current Merkle witnesses. Private wallet inventory, note openings, viewing keys, Merkle paths, and spending keys remain on the local machine.
3. **Official Zcash transaction path.** Rust tooling builds a V6 PCZT from real spendable notes and the shared anchor, maps buyer fills and per-seller change, signs participant contributions, proves, and extracts raw V6 transaction bytes.
4. **Cross-asset USDC leg.** The coordinator verifies the exact USDC escrow funding and payout commitments before allowing ZEC broadcast. After the required ZEC confirmations, the explicit local oracle workflow attests the matching transaction, releases escrowed USDC, and asks the coordinator to finalize only after it verifies the matching release receipt.
5. **Fail-closed status.** A simulated balance, local block, raw-transaction submission, ZEC confirmation, and USDC release are separate states. The legacy experimental assembler is blocked from live broadcast; only the extracted official-library V6 transaction can be submitted through the trusted local workflow.

## Implementation and evidence

| Area | Implemented in repository | What still needs proof |
|---|---|---|
| FBA matching and epoch records | Python API, solver, tests, dashboard | Independent economic/privacy review |
| Wallet scanning | Zebra Testnet RPC scanner, Ironwood note tracking, Merkle witness refresh, private inventory export | Run against a funded synced wallet with real notes |
| PCZT settlement | Rust V6 construction, participant redaction/signing, combination, Halo 2 proof and extraction | Successful build/prove and real transaction acceptance on a live Testnet |
| USDC escrow | Solidity escrow state machine, payout-plan commitment checks, EVM read/preflight | Deploy/configure escrow and fund a test batch |
| Cross-chain completion | Confirmation-gated oracle, release, coordinator finalization, pending-transaction recovery | Execute and archive an end-to-end ZEC+USDC Testnet evidence bundle |
| Automated validation | Python, Rust and Solidity test suites/workflows | The latest GitHub Actions attempts did not start any step because no runner was assigned; they are **not passing test runs** |

The repository is not independently audited, and this software is not a production DEX or trustless atomic swap. The EVM oracle is an explicit trust boundary: the contract relies on the configured oracle to attest to Zebra's observed confirmation. Any committee evaluation should distinguish a working code path from a verified live-chain execution.

## Architecture

~~~
Sealed intents
     |
     v
FBA solver (uniform price + integer pro-rata fills)
     |
     v
Private local settlement plan
     |
     +-------------------------+
     |                         |
     v                         v
Zebra Testnet wallet       USDC escrow preflight
scan / notes / witnesses   exact plan + funding check
     |                         |
     v                         |
Rust PCZT build, participant signatures, Halo 2 proof
     |
     v
Extract V6 transaction -> Zebra broadcast -> required confirmations
     |
     v
Local oracle verifies tx + epoch + payout commitments
     |
     v
EVM attestation -> USDC release receipt -> coordinator verifies -> CLEARED
~~~

The legacy API does not treat an epoch-clear action or a simulated result as settlement success.

## Run the local demo

The local demo demonstrates the matching API and dashboard, **not live ZEC or USDC transfers**.

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

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Inspect the reported settlement status; the local simulator is not Zebra, and the legacy assembler is not live-broadcastable.

## Build and test

~~~bash
cargo build --release --manifest-path darkbatch_crypto/Cargo.toml
cargo test --release --manifest-path darkbatch_crypto/Cargo.toml
python -m compileall -q darkbatch
python -m pytest darkbatch/tests/ -v
~~~

Solidity escrow tests (requires Foundry):

~~~bash
forge test --root contracts -vv
~~~

These commands must be run successfully before treating the corresponding test suites as validated. Unit tests do not replace a real Zebra transaction and USDC escrow integration run.

## Real Testnet workflow

The real-wallet workflow is intentionally explicit and runs beside the user's synced wallet/node:

- [Ironwood wallet scan → private inventory → PCZT → optional Zebra/USDC settlement](docs/IRONWOOD_LOCAL_WALLET_WORKFLOW.md)
- [PCZT settlement implementation notes](docs/LOCAL_PCZT_SETTLEMENT.md)
- [Submission brief for reviewers](docs/SUBMISSION_BRIEF.md)

Use a Zebra **Testnet** node and a funded, correctly configured test escrow only. Keep spending keys and private inventory out of Git, logs, screenshots, and the public coordinator. The **--settle-usdc** switch is an irreversible action: use it only after reviewing the epoch, batch ID, payout commitments, and preflight result.

## Security boundaries

- No automatic simulation fallback for a failed real-network submission.
- No status of **CLEARED** until the coordinator validates the confirmed ZEC transaction and matching USDC release receipt.
- Wallet inventory, note openings, witnesses, PCZTs, and keys are local-only artifacts.
- Pending EVM transaction hashes are persisted locally and polled during recovery rather than replaced automatically.
- No mainnet deployment is recommended before independent protocol, cryptographic, wallet, contract, and economic review.

## License

See [LICENSE](LICENSE).
