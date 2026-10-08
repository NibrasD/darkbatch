# DarkBatch 🛡️⚖️
### Confidential Intent-Based Frequent Batch Auction (FBA) & RFQ Protocol with ZIP-229 Settlement for Shielded Zcash (Ironwood Era)

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--229%20v6%20(0xD884B698)-amber.svg)](https://zips.z.cash/zip-0229)
[![Rust Engine](https://img.shields.io/badge/Rust-pasta__curves%20Pallas-orange.svg)](https://crates.io/crates/pasta_curves)
[![MEV Protection](https://img.shields.io/badge/MEV%20Protection-100%25%20FBA-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 1. Executive Summary & Design Philosophy

**DarkBatch** is an institutional-grade, MEV-free decentralized exchange primitive engineered for the **Zcash Ironwood shielded ecosystem**. Inspired by the venture success of **Archer Exchange** (4th Place DeFi, Colosseum Cypherpunk) and the mathematical foundations of **Frequent Batch Auctions (FBA)**, DarkBatch solves the single greatest barrier facing shielded ZEC adoption: **private, zero-slippage, front-running-immune liquidity**.

### Architectural Positioning & Scope
To maintain complete cryptographic and protocol integrity:
1. **The Off-Chain Matching Layer (FBA / RFQ):** Market participants commit off-chain sealed limit intents. In discrete epochs, an autonomous solver aggregates supply and demand curves to calculate a single **Uniform Clearing Price ($P^*$)**. All inframarginal orders are filled 100%, and pro-rata rationing is applied strictly to marginal orders at $P^*$.
2. **The Settlement Layer (ZIP 229 / Ironwood Adapter):** Fills are compiled into **ZIP-229 Transaction v6** consensus payloads (`0xD884B698`), encoding authentic 820-byte `OrchardAction` descriptors (§ 7.5) with 580-byte encrypted note ciphertexts (`0x03` Ironwood quantum-recoverable format). An operational **Testnet Settlement Adapter** submits raw transactions to live Zcash nodes via JSON-RPC `sendrawtransaction` or verifies them against the internal Ironwood consensus simulator.

---

## 2. Protocol Correctness & Cryptographic Specifications

### A. Authentic Pallas Curve Cryptography (`darkbatch_crypto`)
* Implemented in Rust using `pasta_curves = "0.6"` ($y^2 = x^3 + 5$ over $\mathbb{F}_p$).
* **Protocol-Compliant Generator Derivation (Zcash Specification § 5.4.9.4):**
  $$\mathcal{V}^{\text{Orchard}} = \mathrm{GroupHash}^{\mathbb{P}}(\texttt{"z.cash:Orchard-cv"}, \texttt{"v"})$$
  $$\mathcal{R}^{\text{Orchard}} = \mathrm{GroupHash}^{\mathbb{P}}(\texttt{"z.cash:Orchard-cv"}, \texttt{"r"})$$
  Eliminates non-standard domain separators and complies directly with Zcash consensus.
* **Pedersen Value Commitments:**
  $$C = [v] \cdot \mathcal{V}^{\text{Orchard}} + [r] \cdot \mathcal{R}^{\text{Orchard}}$$
* **Consensus Value Balance Conservation:**
  $$\sum C^{\text{in}} - \sum C^{\text{out}} = [valueBalance] \cdot \mathcal{V} + [bsk_{\text{bundle}}] \cdot \mathcal{R}$$

### B. ZIP 229 Transaction v6 Format (Ironwood Shielded Pool)
Conforms to the official [ZIP 229 Specification](https://zips.z.cash/zip-0229):
* **Header:** `0x80000006` (Overwintered bit set, version 6).
* **Version Group ID:** `0xD884B698` (Mandatory consensus rule per ZIP 229 § 7.1.2).
* **Consensus Branch ID:** `0x2f8b66c3` (NU6.3 Ironwood).
* **Orchard / Ironwood Action Encoding (§ 7.5):** Each action is encoded to **strictly 820 bytes**:
  $$\text{Action} = \underbrace{cv}_{32\text{B}} + \underbrace{nullifier}_{32\text{B}} + \underbrace{rk}_{32\text{B}} + \underbrace{cmx}_{32\text{B}} + \underbrace{ephemeralKey}_{32\text{B}} + \underbrace{encCiphertext}_{580\text{B}} + \underbrace{outCiphertext}_{80\text{B}} = 820\text{ bytes}$$
* **Note Plaintext & Ciphertext (ZIP 2005 / ZIP 212):**
  - Lead Byte: `0x03` (Quantum-recoverable Ironwood note format).
  - Encrypted Ciphertext: $1\text{B lead} + 11\text{B diversifier} + 8\text{B value} + 32\text{B rseed} + 512\text{B memo} + 16\text{B MAC} = 580\text{ bytes}$.
  - Outgoing Ciphertext: 80 bytes.

### C. Strictly 512-Byte Encrypted Memo Receipts
* **ZIP 212 / ZIP 302 Compliance:** Raw memo payload inside the note is strictly 512 bytes.
* **Incoming Viewing Key (`ivk`) Derivation:**
  Receipts are encrypted under the recipient's viewing key via Diffie-Hellman key exchange:
  $$K_{\text{memo}} = \mathrm{KDF}([esk] \cdot ivk_{\text{recipient}})$$
  Ensuring that only the intended counterparty can inspect their fill confirmation.

### D. Zero-Leak Confidential Mempool
* Order prices, trade sizes, and directions are **never broadcast** in cleartext.
* The public API (`/api/v1/epoch/current`) and UI display exclusively sealed Pedersen commitments ($C$) and intent IDs.

### E. Economically Authentic Frequent Batch Auction (FBA)
* **Strict Price Priority:** Inframarginal orders ($P_{\text{buy}} > P^*$ and $P_{\text{sell}} < P^*$) are filled **100%**.
* **Marginal Rationing:** Pro-rata allocation is applied **exclusively to marginal orders** sitting at the boundary price $P^*$.
* **Out-of-the-Money Orders:** Receive 0% fill.
* Eliminates sandwich attacks, front-running, and latency arbitrage entirely.

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
                                                   - 820B OrchardActions (§ 7.5)
                                                   - 580B encCiphertext (lead 0x03)
                                                   - Strictly 512B Memo Receipts
                                                                   │
                                                                   ▼
                                                   [ Testnet Settlement Adapter ]
                                                   - Live RPC sendrawtransaction
                                                   - High-fidelity consensus validation
                                                   - Real testnet txid & block height
```

---

## 4. Verification & Testing

### 1. Running the Rust Cryptographic Suite
```bash
cargo test --manifest-path darkbatch_crypto/Cargo.toml --release
```
* `test_zip229_consensus_constants`: Verifies `VERSION_GROUP_ID_V6 == 0xD884B698`.
* `test_orchard_action_exact_820_bytes`: Verifies exact 820-byte serialization per § 7.5.
* `test_memo_strictly_512_bytes`: Verifies strict 512-byte buffer.
* `test_pedersen_homomorphism`: Verifies Pallas curve additive homomorphism.
* `test_value_balance_conservation`: Verifies value balance and binding key verification.

### 2. Running the Full Python Test Suite
```bash
python -m pytest darkbatch/tests/ -v
```
All 8 unit and end-to-end integration tests pass 100%:
* `test_pedersen_commitment` (Pallas engine with `z.cash:Orchard-cv` derivation)
* `test_strictly_512_byte_encrypted_memo` (strict 512-byte buffer)
* `test_intent_creation_and_signature`
* `test_fba_inframarginal_priority_and_marginal_rationing`
* `test_mev_resistance_and_order_invariance`
* `test_zip228_action_groups_and_v6_bundle` (ZIP 229 v6 bundle with 0xD884B698)
* `test_testnet_settlement_adapter_broadcast` (Testnet broadcast & txid verification)
* `test_full_system_lifecycle` (E2E lifecycle with consensus node simulator)

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
