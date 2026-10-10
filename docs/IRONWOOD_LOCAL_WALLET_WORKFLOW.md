# Real Ironwood wallet → local PCZT settlement workflow

This path uses a local Zebra Testnet node and the official Zcash Rust scanner/PCZT tooling. It does not treat a local balance as a chain transfer.

## Prerequisites

- A synced, NU6.3-capable Zebra Testnet RPC, configured with `ZCASH_TESTNET_RPC_URL` and optionally `ZCASH_TESTNET_RPC_USER` / `ZCASH_TESTNET_RPC_PASS`.
- Rust/Cargo and the repository's pinned Zcash dependencies.
- One locally protected raw 32-byte Orchard/Ironwood spending-key hex file per participating wallet. Do not commit or upload these files.
- The coordinator running with a trusted settlement token and the USDC escrow deployment configured.
- A fully funded USDC escrow batch whose committed plan matches the FBA epoch before broadcasting ZEC.

Build the local Rust binary:

```bash
cargo build --release --manifest-path darkbatch_crypto/Cargo.toml
cargo test --release --manifest-path darkbatch_crypto/Cargo.toml
python -m pytest darkbatch/tests/ -q
```

## Scan wallets locally

Initialize each wallet at a canonical Testnet height **before the notes you need to discover**. An initial checkpoint cannot reveal notes created before that height; older notes need a valid witness imported from a trusted wallet.

```bash
python -m darkbatch.settlement.ironwood_wallet_scan init --state private/alice-state.json --height <checkpoint-height>
python -m darkbatch.settlement.ironwood_wallet_scan sync --state private/alice-state.json
python -m darkbatch.settlement.ironwood_wallet_scan notes --state private/alice-state.json
```

The sync prompts for the spending key, keeps it out of the saved scan state, checks Zebra's canonical block hashes and Ironwood tree state, updates note witnesses, and marks notes spent when their nullifiers appear on chain. The scan state contains sensitive note history and must remain local.

## Export the private inventory for the local PCZT agent

Prepare a private JSON array, for example `private/wallet-configs.json`:

```json
[
  {
    "state_path": "private/alice-state.json",
    "spending_key_file": "private/alice-spending-key.hex",
    "shielded_address": "<Alice's exact Testnet Unified Address>",
    "address_index": 0,
    "change_index": 1
  },
  {
    "state_path": "private/bob-state.json",
    "spending_key_file": "private/bob-spending-key.hex",
    "shielded_address": "<Bob's exact Testnet Unified Address>",
    "address_index": 0,
    "change_index": 1
  }
]
```

All wallet states must be scanned to the **same current canonical Zebra tip** and have the same current Ironwood root. The configured shielded address must match the locally derived address at its specified index. The exporter refuses stale scan states, missing/stale Merkle witnesses, mismatched roots, malformed key files, or an output inventory path that already exists.

```bash
python -m darkbatch.settlement.ironwood_wallet_scan inventory --wallet-configs private/wallet-configs.json --out private/wallet_inventory.json
```

If the FBA plan charges a ZEC solver fee, also provide a valid raw 43-byte receiver with `--solver-fee-receiver-hex <86-hex-chars>`.

The inventory contains Full Viewing Keys, note openings, Merkle paths, wallet addresses and local spending-key file paths. It is a private local artifact: **never send it to the coordinator or commit it to Git**.

## Build, prove, and broadcast

The inventory format is consumed by the trusted local agent. First build/prove without broadcasting:

```bash
python -m darkbatch.settlement.local_pczt_agent --epoch-id <epoch-id> --wallet-inventory private/wallet_inventory.json --workdir private/pczt-<epoch-id>
```

After reviewing the returned build/proof reports and ensuring the exact USDC plan is fully funded on chain, an explicit Testnet broadcast can be requested:

```bash
python -m darkbatch.settlement.local_pczt_agent --epoch-id <epoch-id> --wallet-inventory private/wallet_inventory.json --workdir private/pczt-<epoch-id> --broadcast --quote-batch-id <bytes32-batch-id> --wait-for-confirmation 120
```

The coordinator verifies the PCZT build/proof report, matching transaction ID, current Testnet consensus branch, and funded USDC escrow before submitting raw V6 bytes to Zebra. Broadcast acceptance is not confirmation. The USDC leg remains unsettled until the separate local oracle verifies the confirmed ZEC transaction and the corresponding on-chain USDC release. Do not report the epoch as settled until the API verifies both legs and persists the resulting state.

This workflow is a local integration path, not a substitute for a security audit. Do not use mainnet funds without independent review of the Rust build, participant authorization flow, coordinator, Zebra integration, and escrow/oracle contracts.
