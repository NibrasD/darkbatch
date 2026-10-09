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

## 5. Standalone real Ironwood Testnet wallet path

The coordinator above remains **simulation-only**. A separate local CLI now supports building and broadcasting a normal single-wallet Ironwood transfer from real notes. It does not yet turn multiple users' FBA fills into a collaborative atomic settlement.

**Requirements:** a NU6.3+-capable Zebra Testnet RPC endpoint with `getblockchaininfo`, `getblockhash`, `getblock`, `z_gettreestate`, `sendrawtransaction`, and `getrawtransaction`. Never put spending keys in API requests or on the public coordinator.

### 1. Build the Rust engine

```bash
cargo build --manifest-path darkbatch_crypto/Cargo.toml --release
```

Configure the RPC endpoint and credentials in your local shell. Keep credentials private.

PowerShell:
```powershell
$env:ZCASH_TESTNET_RPC_URL = "http://127.0.0.1:18232"
$env:ZCASH_TESTNET_RPC_USER = "your-rpc-user"
$env:ZCASH_TESTNET_RPC_PASS = "your-rpc-password"
```

Use the correct URL and credentials for your own node. The project does not provide a public RPC endpoint.

### 2. Check or derive an Ironwood-capable Testnet address

```bash
python -m darkbatch.settlement.ironwood_wallet_sync address
```

The prompt requests the 32-byte raw Orchard-protocol `SpendingKey` in hex (input is hidden). This initial integration is **not** a BIP39/ZIP32 seed importer; use only a key you control and can safely back up. The output provides a standard Testnet Unified Address. Fund it with Testnet ZEC using a suitable Testnet faucet or wallet.

### 3. Initialize before receiving funds and synchronize notes

Choose a canonical activation-era height **before the transaction that funds this address**. The scanner will not discover older notes that precede the checkpoint.

```bash
python -m darkbatch.settlement.ironwood_wallet_sync init --state .\\darkbatch-ironwood-testnet.json --height 4134000
python -m darkbatch.settlement.ironwood_wallet_sync sync --state .\\darkbatch-ironwood-testnet.json --max-blocks 100
python -m darkbatch.settlement.ironwood_wallet_sync notes --state .\\darkbatch-ironwood-testnet.json
```

Repeat `sync` with reasonable block limits until the state reports that it has caught up with the node tip. The tool compares its reconstructed Ironwood tree state with Zebra before advancing the checkpoint; if they diverge, it refuses to use stale witnesses.

### 4. Build (without broadcasting) a transfer

Create an `outputs.json` file. The destination may be a normal **Testnet Unified Address** containing an Orchard-protocol receiver:

```json
[
  {
    "recipient_address": "u1...REPLACE_WITH_REAL_TESTNET_UNIFIED_ADDRESS",
    "value_zat": 10000,
    "memo_hex": ""
  }
]
```

The address above is a placeholder; replace it with a real address. One ZEC is 100,000,000 zatoshis. Then choose unspent note IDs shown by the `notes` command:

```bash
python -m darkbatch.settlement.ironwood_wallet_sync build --state .\\darkbatch-ironwood-testnet.json --notes "NOTE_ID_1,NOTE_ID_2" --outputs-json outputs.json --out built-tx.json
```

The command validates the live tip, anchor, note witnesses, key ownership, values, change and fee before asking the **official `zcash_primitives` builder** to produce one authorized v6 transaction. It saves the raw transaction locally and does not broadcast it.

### 5. Broadcast and confirm

After checking the recipient and amount:

```bash
python -m darkbatch.settlement.ironwood_wallet_sync broadcast --tx-file built-tx.json
python -m darkbatch.settlement.ironwood_wallet_sync status --txid YOUR_64_HEX_TXID
```

A successful `sendrawtransaction` request is reported as `BROADCAST_PENDING`, with zero confirmations. The `status` command queries `getrawtransaction` from the configured Zebra node and marks a transaction confirmed only when the node reports positive confirmations. Depending on your node's transaction-index configuration, looking up an already-mined transaction may require `txindex=1`.

**Security and scope:** the scanner/wallet state contains notes and witnesses but is not a seed backup. Keep the spending key offline/private and back up the original key safely. The initial builder accepts inputs from one wallet only; it is a real-transaction path for testing ordinary Ironwood transfers, not yet a non-custodial multi-party FBA settlement. A collaborative-signing design is needed before multiple traders' notes can fund one atomic FBA batch without handing their spending keys to a coordinator.

---

## 6. Collaborative Ironwood PCZT workflow (manual Testnet integration)

The Rust PCZT path supports a single v6 transaction whose real inputs are signed separately by their owners. It does **not** automatically turn the current FBA solver's simulated fills into a batch transaction yet. Use it as a local, manually coordinated Testnet workflow while keeping the public FBA API out of the key-handling path.

**Privacy warning:** PCZT creation needs input-note openings and each input's Full Viewing Key. The local assembler sees those values. Never upload them to a public coordinator or send them to an untrusted party. Participants should receive only their redacted PCZT copy, review all public output effects and the exact sighash locally, and sign only their own input.

### 1. Create a proposed PCZT locally

Build the Rust engine first. Each participant should scan their own wallet locally and export sensitive viewing material only for the trusted local assembler, if that privacy trade-off is acceptable:

```bash
python -m darkbatch.settlement.ironwood_pczt export-fvk --out private-fvk.json
python -m darkbatch.settlement.ironwood_wallet_sync notes --state .\\darkbatch-ironwood-testnet.json
```

Use the scanner's protected state file to obtain the selected note's receiver, value, rho, rseed and nullifier. Do not publish that state file. Then make a private request file from actual unspent Ironwood V3 notes and real recipient addresses. The structure is:

```json
{
  "network": "testnet",
  "target_height": 4134011,
  "expiry_height": 4134031,
  "spends": [
    {
      "input_id": "input-alice-1",
      "full_viewing_key_hex": "FVK_HEX_FROM_LOCAL_WALLET",
      "note_address_raw_hex": "86_HEX_CHARACTERS_FOR_RAW_43_BYTE_RECEIVER",
      "value_zat": 200000,
      "rho_hex": "64_HEX_CHARACTERS",
      "rseed_hex": "64_HEX_CHARACTERS",
      "nullifier_hex": "64_HEX_CHARACTERS"
    }
  ],
  "outputs": [
    {
      "output_id": "recipient-1",
      "recipient_address": "REAL_TESTNET_UNIFIED_ADDRESS",
      "value_zat": 180000,
      "memo_hex": ""
    },
    {
      "output_id": "change",
      "recipient_address": "SENDER_TESTNET_UNIFIED_ADDRESS",
      "value_zat": 10000,
      "memo_hex": ""
    }
  ]
}
```

This JSON is a schema example only; replace every placeholder with real wallet data and use the current node tip plus one for `target_height`. The sum of inputs minus outputs must equal the official ZIP-317 fee exactly. Include an explicit change output when needed.

```bash
python -m darkbatch.settlement.ironwood_pczt create --request pczt-request.json --out unsigned-pczt.json
python -m darkbatch.settlement.ironwood_pczt inspect --pczt unsigned-pczt.json
```

### 2. Prepare and sign each participant's input

For each participant, create a separate redacted copy using that participant's own nullifier:

```bash
python -m darkbatch.settlement.ironwood_pczt prepare-signer --pczt unsigned-pczt.json --nullifier PARTICIPANT_NULLIFIER --out participant-to-sign.json
```

Review the returned action manifest, recipient outputs, values, fee and `sighash_hex`. On that participant's trusted machine, use the redacted PCZT and the exact reviewed sighash:

```bash
python -m darkbatch.settlement.ironwood_pczt sign --pczt participant-to-sign.json --nullifier PARTICIPANT_NULLIFIER --sighash REVIEWED_SIGHASH_HEX --out participant-signed.json
```

Repeat separately for every real input owner. Do not pass any spending key through the coordinator or command-line arguments; the CLI asks for it via hidden input.

### 3. Combine signatures and finalize against a fresh anchor

Bring the participant-signed PCZT copies together on the trusted local finalizer:

```bash
python -m darkbatch.settlement.ironwood_pczt combine --pczts alice-signed.json bob-signed.json --nullifiers ALICE_NULLIFIER,BOB_NULLIFIER --out combined-pczt.json
```

Create a private `finalize-request.json` from the combined PCZT and the **same current canonical Ironwood root** and one witness for every required input:

```json
{
  "pczt_hex": "PCZT_HEX_FROM_COMBINED_FILE",
  "anchor_hex": "CURRENT_64_HEX_IRONWOOD_ROOT",
  "required_nullifiers_hex": [
    "ALICE_64_HEX_NULLIFIER",
    "BOB_64_HEX_NULLIFIER"
  ],
  "witnesses": [
    {
      "nullifier_hex": "ALICE_64_HEX_NULLIFIER",
      "witness_position": 1,
      "witness_auth_path_hex": ["32_BYTE_HEX_NODE_0", "REPLACE_WITH_31_MORE_NODES"]
    },
    {
      "nullifier_hex": "BOB_64_HEX_NULLIFIER",
      "witness_position": 2,
      "witness_auth_path_hex": ["32_BYTE_HEX_NODE_0", "REPLACE_WITH_31_MORE_NODES"]
    }
  ]
}
```

The witness data must come from each participant's current local wallet scan and match that canonical root. The abbreviated values above are placeholders, **not valid witness arrays**.

```bash
python -m darkbatch.settlement.ironwood_pczt finalize --request finalize-request.json --out finalized-tx.json
python -m darkbatch.settlement.ironwood_pczt broadcast --tx-file finalized-tx.json
python -m darkbatch.settlement.ironwood_wallet_sync status --txid YOUR_64_HEX_TXID
```

Finalization asks the official PCZT prover and transaction extractor to prove and serialize the same signed transaction. The broadcast step decodes the raw bytes and checks its txid before contacting Zebra; broadcast acceptance still is not a mined confirmation.

**Limit:** this operational PCZT toolchain is separate from the FBA coordinator. The coordinator still emits `SIMULATED_ONLY`; automatic matching-to-PCZT construction, a privacy-preserving participant input workflow, and verified payment of any non-ZEC quote leg remain to be integrated before claiming a full atomic FBA exchange.

---

## 7. Local FBA simulation

Start the coordinator API:

```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
```

Seed and inspect simulated order flow with the project CLI. Any result from the local node model is simulation data, not a Zcash transaction, block, confirmation, or consensus decision.
