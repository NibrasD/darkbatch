# DarkBatch 🛡️⚖️
### Experimental FBA / PCZT Settlement Prototype — Live Settlement Disabled

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--229%20v6%20(0xD884B698)-amber.svg)](https://zips.z.cash/zip-0229)
[![Rust Engine](https://img.shields.io/badge/Rust-pasta__curves%20Pallas-orange.svg)](https://crates.io/crates/pasta_curves)
[![Stage](https://img.shields.io/badge/stage-experimental--prototype-amber.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

> **Current implementation status — not production-ready for real ZEC settlement**
>
> The FBA matching engine and cryptographic experiments are a prototype. The built-in wallets, balances, notes, anchors and mined blocks are local simulation data; the local simulator is **not Zebra** and does not verify Zcash consensus.
>
> The legacy FBA assembler still produces experimental transaction-shaped data and is blocked from live broadcast. A separate Rust tool now uses the official Zcash transaction builder and PCZT roles to construct a V6 PCZT from supplied real notes, Merkle witnesses, recipient outputs and per-owner change outputs; it can apply signatures locally, create an Ironwood Halo 2 proof, and extract raw V6 transaction bytes. This tool is not integrated with epoch clearing, does not scan for unspent notes, and includes an official PCZT contribution combiner, but participant PCZT files have not been redacted to remove other owners' Note metadata, so this is not yet a privacy-preserving distributed protocol.
>
> Passing unit tests demonstrates the tested local logic only; it is not evidence that a transaction is accepted by Zebra or can spend real ZEC. Do not use this prototype for real funds.
>
> The API deliberately refuses to claim FBA settlement until automatic spendable-note selection, a privacy-preserving/redacted participant contribution flow, automatic wiring from epoch clearing to the FBA PCZT builder, activated Zebra submission/confirmation, and the quote-asset (USDC) settlement leg are integrated and tested. A separate local raw-V6 submitter can send a manually extracted transaction to Zebra, but it does not record an FBA epoch.

## 1. Executive Summary & Design Philosophy

**DarkBatch** is an experimental FBA matching prototype exploring private order matching and shielded Zcash settlement. It explores uniform-price batch matching for shielded Zcash. Real ZEC settlement is not implemented end-to-end and live transaction broadcasting is deliberately disabled.

### Intended Architecture (not end-to-end complete)
The following describes the intended design; it is not a claim of production or consensus correctness:
1. **The Off-Chain Matching Layer (FBA / RFQ):** Market participants commit off-chain sealed limit intents. In discrete epochs, an autonomous solver aggregates supply and demand curves to calculate a single **Uniform Clearing Price ($P^*$)**. All inframarginal orders are filled 100%, and pro-rata rationing is applied strictly to marginal orders at $P^*$.
2. **Settlement tools:** The legacy assembler remains unsafe and blocked from live broadcast. Local Rust commands can build a general PCZT or map supplied buyer fills and per-owner seller fills to ZEC outputs/change, combine PCZT contributions, sign, prove, and extract V6 bytes. They rely on caller-supplied real notes/witnesses and are not invoked automatically by the FBA API.
3. **Execution transparency:** Local simulation, raw-transaction broadcast and block confirmation are separate states. Only the local raw-V6 submitter sends an extracted transaction to Zebra; its RPC acceptance is not a confirmation or proof that the USDC leg settled.

---

## 2. Experimental Cryptographic Work (not a consensus implementation)

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
Trader B (Seller) ─── Sealed Limit Intent ────┼──> [ DarkBatch local sealed-intent prototype ]
Trader C (Whale)  ─── Sealed Limit Intent ────┘                   │
                                                                   ▼
                                                       [ Batch Solver Engine ]
                                                       - Solves Uniform Price P*
                                                       - Inframarginal filled 100%
                                                       - Marginal prorated
                                                                   │
                                                                   ▼
                                                   [ Legacy FBA adapter — LIVE BLOCKED ]
                                                   - Must not broadcast generated bundle bytes
                                                                   │
                                                                   ▼
                                                   [ Local official PCZT tools ]
                                                   - Buyer-fill ZEC outputs + per-owner seller change
                                                   - ZIP 317 fee check + real witness-to-anchor validation
                                                   - Local participant signatures + official proof/extraction
                                                                   │
                                                                   ▼
                                                   [ Optional local Zebra Testnet submitter ]
                                                   - Broadcast != confirmation
                                                   - ZEC confirmation != USDC settlement
```

---

## 4. Verification & Testing

### 1. Running the Rust Cryptographic Suite
```bash
cargo test --manifest-path darkbatch_crypto/Cargo.toml --release
```
The Rust tests cover components of the repository; they do not establish that an assembled transaction is accepted by Zebra or spends real ZEC.
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
The Python unit and end-to-end tests exercise local simulation. They are not live Testnet transaction tests.
* `test_pedersen_commitment` (Pallas engine with `z.cash:Orchard-cv` derivation)
* `test_strictly_512_byte_encrypted_memo` (strict 512-byte buffer)
* `test_intent_creation_and_signature`
* `test_fba_inframarginal_priority_and_marginal_rationing`
* `test_mev_resistance_and_order_invariance`
* `test_zip228_action_groups_and_v6_bundle` (experimental v6-shaped bundle and byte lengths; not a real-note decrypt test)
* `test_testnet_settlement_adapter_broadcast` (explicitly enabled local simulation receipt)
* `test_nu6_3_consensus_and_crypto_integrity` (constant/byte-shape checks in the local simulator; not a Zebra consensus or signature-verification test)
* `test_full_system_lifecycle` (local simulator lifecycle; not real node consensus)

---

## 5. Local Demo (not a live Testnet settlement)

The official-library PCZT builder/signing/combiner/proving path, the FBA buyer-output/seller-change mapping tool, and the local raw-V6 Testnet submitter are documented in [docs/LOCAL_PCZT_SETTLEMENT.md](docs/LOCAL_PCZT_SETTLEMENT.md). The workflow still requires real spendable notes and current Merkle witnesses supplied by a trusted local wallet/scanner; it does not auto-discover notes or settle the USDC leg. The legacy FBA API remains blocked from live settlement.

### 1. Start Coordinator API
```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
```

### 2. Run CLI Operations
```bash
# Seed realistic sealed liquidity
python darkbatch/cli/darkbatch_cli.py epoch seed

# View local intent commitments (privacy is not independently audited)
python darkbatch/cli/darkbatch_cli.py epoch status

# Attempt local FBA clear; live settlement is intentionally blocked
python darkbatch/cli/darkbatch_cli.py epoch clear
```

### 3. Web Dashboard
Navigate to `http://127.0.0.1:8000` to interact with:
* Local intent preview; not an audited zero-leak guarantee.
* Experimental supply/demand depth chart showing an indicative $P^*$.
* Ironwood block explorer with Action Groups and 512-byte memo decrypter using wallet IVKs.
