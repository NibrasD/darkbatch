# DarkBatch 🛡️⚖️
### Confidential Intent-Based Frequent Batch Auction (FBA) prototype targeting Zcash Ironwood

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--229%20v6%20(0xD884B698)-amber.svg)](https://zips.z.cash/zip-0229)
[![Rust Engine](https://img.shields.io/badge/Rust-pasta__curves%20Pallas-orange.svg)](https://crates.io/crates/pasta_curves)
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 1. Current Status & Design Scope

**Important: the current repository is an FBA matching prototype with an Ironwood-targeted simulation path, not yet a consensus-ready Zcash transaction builder.** Do not use its simulated wallet balances, generated IDs, local block records, or intent commitments as proof of on-chain settlement.

- **Ironwood is the new shielded pool introduced in NU6.3 and remains the target pool under later v6-capable upgrades.** The Rust `orchard` crate is a code dependency exposing shared protocol primitives and an `ironwood_v3()` bundle version; using that crate does not by itself make a transaction an Ironwood consensus transaction. The official Rust builder selects the active branch ID from the target height (NU6.3 `0x37A5165B` or NU7 `0x77190AD9`) instead of hardcoding the NU6.3 branch for every height.
- **Available now:** off-chain signed intent submission, FBA matching, epoch coordination, and deterministic simulation records.
- **New Rust integration point:** `darkbatch_crypto::build_ironwood_transaction` delegates transaction construction, proof/signature generation, and serialization to the official `zcash_primitives` v6 builder when supplied with real Ironwood spend notes, matching Merkle witnesses, authorization keys, proving implementations, and a fee rule. This interface is not yet wired to the Python coordinator or its simulated wallet.
- **Not yet implemented end-to-end:** spending real Ironwood notes, acquiring valid note-tree Merkle witnesses, building the exact set of actions in one official Ironwood bundle, generating the proof for that same bundle, deriving valid spend/binding authorization from the matching witnesses and value commitments, serializing the exact authorized transaction, and verifying it against a live NU6.3-capable Zebra node.
- The settlement builder therefore returns `SIMULATED_ONLY`, `tx_id: null`, and no raw transaction. The broadcast adapter rejects incomplete bundles. This is intentional fail-closed behavior, not a live settlement failure.
- The local node is a simulator, **not Zebra**. Simulated block heights, anchors, and duplicate-nullifier checks are not evidence of consensus acceptance.
- Any claims elsewhere in older project notes about authentic transactions, mined testnet settlements, or full consensus validation should be considered unverified until backed by authoritative ZIP test vectors and successful live-node acceptance.

### Architectural Roadmap

1. **Off-chain matching:** sealed signed intents are matched in discrete epochs using a uniform clearing price and marginal pro-rata rationing.
2. **Ironwood wallet integration:** obtain spendable Ironwood notes and valid witnesses from a real wallet/node; recipient viewing keys alone are not spend authority.
3. **Authoritative settlement:** construct spends and outputs through the official Ironwood implementation, generate the proof and signatures for that exact bundle, serialize that same authorized bundle, verify ZIP vectors, and only then allow `sendrawtransaction`.
4. **Explicit execution states:** `SIMULATED_ONLY` is never presented as mined, confirmed, or consensus-verified.

---

## 2. Cryptography status

The repository contains a Rust crate with Pallas/RedPallas operations and uses the Rust `orchard` crate as a dependency. That is not, by itself, evidence that every local helper implements the Ironwood consensus rules.

In particular, no end-to-end consensus claim should be inferred from ciphertext sizes, nonzero signatures, deterministic hashes, local anchors, or a proof generated for a different bundle. ZIP/consensus conformance requires authoritative test vectors and validation of the exact serialized transaction by a compatible Zebra node.

Protocol-critical Python wrappers now require the compiled Rust engine and refuse the old hash-shaped fallback values when the engine is missing or errors. Build the engine first:

```bash
cargo build --manifest-path darkbatch_crypto/Cargo.toml --release
```

## 3. Current execution flow

```text
Signed off-chain intent
        |
        v
FBA solver (uniform clearing price and marginal allocation)
        |
        v
Deterministic simulation record
  status = SIMULATED_ONLY
  tx_id = null
  raw_tx_hex = empty
        |
        v
No balance mutation, no simulated mining, no RPC broadcast
```

The Rust entry point now delegates transaction-level operations to the official builder, but the coordinator still has no real Ironwood notes, current Merkle witnesses, spend keys, or configured proving/fee providers to pass into it. Until that wallet/node integration is complete, settlement remains simulation-only.

## 4. Tests

Build and test the Rust crate:

```bash
cargo test --manifest-path darkbatch_crypto/Cargo.toml --all-targets
```

Run Python tests after building the Rust engine:

```bash
python -m pip install pytest cryptography fastapi pydantic uvicorn
python -m pytest -q
```

The test suite should prove that matching remains available while incomplete settlements are rejected. Passing these tests does **not** establish live Zebra acceptance. The GitHub Actions workflow builds the native engine before running both suites; inspect its actual run result before describing the branch as passing.

## 5. Local development

Start the coordinator API:

```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
```

Seed and inspect simulated order flow with the project CLI. Any result from the local node model is simulation data, not a Zcash transaction, block, confirmation, or consensus decision.
