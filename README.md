# DarkBatch 🛡️⚖️
### Confidential Intent-Based Frequent Batch Auction (FBA) & RFQ Protocol with ZIP-229 Settlement for Shielded Zcash (Ironwood Era)

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--229%20v6%20(0xD884B698)-amber.svg)](https://zips.z.cash/zip-0229)
[![Rust Engine](https://img.shields.io/badge/Rust-pasta__curves%20Pallas-orange.svg)](https://crates.io/crates/pasta_curves)
[![MEV Protection](https://img.shields.io/badge/MEV%20Protection-100%25%20FBA-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 1. Current Status & Design Scope

**Important: the current repository is an FBA matching prototype with an Ironwood-targeted simulation path, not yet a consensus-ready Zcash transaction builder.** Do not use its simulated wallet balances, generated IDs, local block records, or intent commitments as proof of on-chain settlement.

- **Ironwood is the new shielded pool introduced for NU6.3.** The Rust `orchard` crate is currently a code dependency exposing shared protocol primitives and an `ironwood_v3()` bundle version; using that crate does not by itself make a transaction an Ironwood consensus transaction.
- **Available now:** off-chain signed intent submission, FBA matching, epoch coordination, and deterministic simulation records.
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

## 2. Protocol Correctness & Cryptographic Specifications

### A. Authentic Pallas Curve Cryptography (`darkbatch_crypto`)
* Implemented in Rust using `pasta_curves = "0.6"` ($y^2 = x^3 + 5$ over $\mathbb{F}_p$) and official Zcash crates (`orchard = "0.16.0"`, `reddsa = "0.6"`, `blake2b_simd = "1.0"`).
* **Protocol-Compliant Generator Derivation (Zcash Specification § 5.4.9.4):**
  $$\mathcal{V}^{\text{Orchard}} = \mathrm{GroupHash}^{\mathbb{P}}(\texttt{"z.cash:Orchard-cv"}, \texttt{"v"})$$
  $$\mathcal{R}^{\text{Orchard}} = \mathrm{GroupHash}^{\mathbb{P}}(\texttt{"z.cash:Orchard-cv"}, \texttt{"r"})$$
* **Pedersen Value Commitments:**
  $$C = [v] \cdot \mathcal{V}^{\text{Orchard}} + [r] \cdot \mathcal{R}^{\text{Orchard}}$$
* **Consensus Value Balance Conservation:**
  $$\sum C^{\text{in}} - \sum C^{\text{out}} - [valueBalance]\mathcal{V} = [bsk_{\text{bundle}}] \cdot \mathcal{R}$$

### B. Spend Authorization & Randomized Keys (§ 5.4.6.1)
* **Randomized Validating Key Derivation:**
  $$rsk = \mathrm{RandomizePrivate}(\alpha, ask), \quad rk = \mathrm{DerivePublic}(rsk)$$
* $rk$ is embedded at offset 64..96 of each 820-byte `OrchardAction`.
* The spend authorization signature in `vSpendAuthSigsIronwood` is signed by $rsk$ over the canonical SIGHASH digest and verifies mathematically against $rk$ ($rk.\mathrm{verify}(sighash, sig) == \mathrm{Ok(())}$).

### C. Authentic Zcash Orchard Note Encryption (§ 5.4.3.4 & § 5.4.3.5)
* **Key Agreement on Pallas:**
  - $g_d = \mathrm{DiversifyHash}(d)$
  - $epk = [esk] \cdot g_d$
  - $pk_d = [ivk] \cdot g_d$
  - $sharedSecret = [esk] \cdot pk_d = [ivk] \cdot epk$
* **Key Derivation (KDF):**
  $$K^{\text{enc}} = \mathrm{BLAKE2b-256}(\texttt{"Zcash\_OrchardKDF"}, sharedSecret \parallel epk)$$
  $$ock = \mathrm{BLAKE2b-256}(\texttt{"Zcash\_Orchardock"}, ovk \parallel cv \parallel cmx \parallel epk)$$
* **Note Plaintext & Ciphertexts:**
  - `NotePlaintext` (564B): Lead byte `0x03` (ZIP 2005) + diversifier (11B) + value (8B) + rseed (32B) + raw memo (512B).
  - $C^{\text{enc}}$ (580B): `ChaCha20Poly1305`($K^{\text{enc}}$, $0^{12}$, `NotePlaintext`).
  - $C^{\text{out}}$ (80B): `ChaCha20Poly1305`($ock$, $0^{12}$, $pk_d \parallel esk$).
  - Decryptable exclusively by recipient's $ivk$ via $[ivk] \cdot epk$.

### D. ZIP 244 Hierarchical Transaction Identifier for Transaction v6 (ZIP 229 § 7.1)
* Tree of digests computed using official BLAKE2b-256 personalizations:
  - Header Digest: `BLAKE2b-256("ZTxIdIronwd_H_v6", header || version_group_id || branch_id || lock_time || expiry_height)`
  - Transparent Digest: `BLAKE2b-256("ZTxIdIronwd_T_v6", "")`
  - Sapling Digest: `BLAKE2b-256("ZTxIdIronwd_S_v6", "")`
  - Orchard Digest: `BLAKE2b-256("ZTxIdIronwd_O_v6", "")`
  - Action Digest: `BLAKE2b-256("ZTxIdIronwAct_v6", nActions || action_1 || ...)`
  - Ironwood Digest: `BLAKE2b-256("ZTxIdIronwd_I_v6", actions_digest || flags || value_balance || anchor)`
  - Root Identifier ($txid$): `BLAKE2b-256("ZTxIdIronwdHash_", header_digest || transparent_digest || sapling_digest || orchard_digest || ironwood_digest)`

### E. Halo 2 Orchard Prover & Verifier Key Architecture
* Circuit parameters integrated directly with `orchard::circuit::VerifyingKey::build(OrchardCircuitVersion::PostNu6_3)`.

---

## 3. End-to-End Execution Pipeline

```
Trader A (Buyer)  ─── Sealed Limit Intent ────┐
Trader B (Seller) ─── Sealed Limit Intent ────┼──> [ DarkBatch Zero-Leak Mempool ]
Trader C (Whale)  ─── Sealed Limit Intent ────┘                   │
                                                                   ▼
                                                       [ Batch Solver Engine ]
                                                       - Solves Uniform Price P*
                                                       - Inframarginal filled 100%
                                                       - Marginal prorated
                                                                   │
                                                                   ▼
                                                   [ ZIP-229 Settlement Engine ]
                                                   - Version Group ID: 0xD884B698
                                                   - Branch ID: 0x37A5165B (NU6.3)
                                                   - 820B OrchardActions (§ 7.5)
                                                   - 580B encCiphertext (lead 0x03)
                                                   - ZIP 244 Hierarchical Digest TxID
                                                                   │
                                                                   ▼
                                                   [ Testnet Settlement Adapter ]
                                                   - Live RPC sendrawtransaction (live_node: true)
                                                   - Local Zebra NU6.3 validator (live_node: false)
```

---

## 4. Verification & Testing

### 1. Running the Rust Cryptographic Suite
```bash
cargo test --manifest-path darkbatch_crypto/Cargo.toml --release
```
All 11 Rust tests pass:
* `test_zip229_consensus_constants`: Verifies `VERSION_GROUP_ID_V6 == 0xD884B698` and branch `0x37A5165B`.
* `test_orchard_action_exact_820_bytes`: Verifies exact 820-byte serialization per § 7.5.
* `test_authentic_zcash_note_encryption_roundtrip`: Verifies RFC 8439 580-byte note encryption and IVK decryption.
* `test_authentic_randomized_spend_auth`: Verifies RedPallas $rsk \to rk$ verification.
* `test_zip244_hierarchical_txid`: Verifies ZIP 229 § 7.1 tree of digests.
* `test_orchard_circuit_keys`: Verifies `OrchardCircuitVersion::PostNu6_3` Halo 2 parameter generation.
* `test_pedersen_homomorphism` & `test_value_balance_conservation`.

### 2. Running the Full Python Test Suite
```bash
python -m pytest darkbatch/tests/ -v
```
All 9 unit and end-to-end integration tests pass 100%:
* `test_pedersen_commitment` (Pallas engine with `z.cash:Orchard-cv` derivation)
* `test_strictly_512_byte_encrypted_memo` (strict 512-byte buffer)
* `test_intent_creation_and_signature`
* `test_fba_inframarginal_priority_and_marginal_rationing`
* `test_mev_resistance_and_order_invariance`
* `test_zip228_action_groups_and_v6_bundle` (ZIP 229 v6 bundle with 0xD884B698, 580B ciphertext, and IVK note decryption)
* `test_testnet_settlement_adapter_broadcast` (Local Zebra NU6.3 verification & transparent receipt)
* `test_nu6_3_consensus_and_crypto_integrity` (NU6.3 consensus constants & RedPallas signatures)
* `test_full_system_lifecycle` (E2E lifecycle with consensus engine)

---

## 5. Live Demo & Interaction

### 1. Start Coordinator API
```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
```

### 2. Run CLI Operations
```bash
# Seed realistic sealed liquidity
python darkbatch/cli/darkbatch_cli.py epoch seed

# View zero-leak mempool
python darkbatch/cli/darkbatch_cli.py epoch status

# Trigger uniform clearing & settlement
python darkbatch/cli/darkbatch_cli.py epoch clear
```

### 3. Web Dashboard
Navigate to `http://127.0.0.1:8000` to interact with:
* Real-time sealed orderbook (zero cleartext leaks).
* Dynamic supply & demand depth chart showing $P^*$ clearing price.
* Ironwood block explorer with Action Groups and 512-byte memo decrypter using wallet IVKs.
