# DarkBatch 🛡️⚖️
### Confidential Intent-Based Batch Auction & RFQ Protocol for Shielded Zcash (Ironwood Era)

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--228%20%7C%20ZIP--229%20v6-amber.svg)](https://zips.z.cash/zip-0228)
[![Rust Engine](https://img.shields.io/badge/Rust-pasta__curves%20Pallas-orange.svg)](https://crates.io/crates/pasta_curves)
[![MEV Protection](https://img.shields.io/badge/MEV%20Protection-100%25%20FBA-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 1. Executive Summary

**DarkBatch** is an institutional-grade, MEV-free exchange primitive engineered for the **Zcash Ironwood shielded ecosystem**. Inspired by the venture success of **Archer Exchange** (4th Place DeFi, Colosseum Cypherpunk) and the mathematical foundations of **Frequent Batch Auctions (FBA)**, DarkBatch solves the single greatest barrier facing shielded ZEC adoption: **private, zero-slippage, front-running-immune liquidity**.

Instead of routing orders through transparent order books or automated market makers where high-frequency bots front-run, sandwich, and leak transaction volumes, DarkBatch allows market participants to commit **off-chain sealed limit intents**. In discrete 30-second epochs, an off-chain solver matches supply and demand curves to compute a **single Uniform Clearing Price ($P^*$)**. All matched orders execute simultaneously at $P^*$, and settlement is compiled into an atomic **Zcash Transaction v6 (ZIP 229 / ZIP 228)** settling directly into the **Ironwood Shielded Pool**.

---

## 2. Key Architectural Innovations & Protocol Correctness

### A. Real Pallas Elliptic Curve Cryptography (`darkbatch_crypto`)
* Powered by Rust's `pasta_curves` crate ($y^2 = x^3 + 5$ over $\mathbb{F}_p$).
* **Pedersen Value Commitments:**
  $$C = [v] \cdot \mathcal{V} + [r] \cdot \mathcal{R}$$
  where $\mathcal{V}$ and $\mathcal{R}$ are independent curve generator points.
* **Consensus Value Balance Verification:**
  $$\sum C^{\text{in}} - \sum C^{\text{out}} = [valueBalance] \cdot \mathcal{V} + [bsk_{\text{bundle}}] \cdot \mathcal{R}$$
* **ZIP 228 Additive Binding Keys:**
  $$\mathsf{bsk}_{\text{bundle}} = \sum \mathsf{bsk}_i \pmod{q}$$
  proving on-chain value conservation across arbitrary matching pairs without revealing order quantities.

### B. Authentic ZIP 228 Swap Bundles & Action Groups
Conforming directly to the official [ZIP 228 Specification](https://zips.z.cash/zip-0228):
* Every Swap Order creates an `ActionGroup` containing:
  1. `SwapAction`: Spends the offered note (nullifier, randomized validating key $rk$, note commitment $cm^*$) and attaches an encrypted execution receipt.
  2. `FeeAction`: Contains explicit Matcher Fee and Miner Fee in ZEC to balance the transaction.

### C. Strictly 512-Byte Encrypted Memos (ZIP 212 / ZIP 302 Standard)
* The entire encrypted memo buffer is **strictly 512 bytes in total**:
  $$\text{Memo} = \underbrace{\text{Nonce}}_{12\text{ bytes}} + \underbrace{\text{Ciphertext}}_{484\text{ bytes}} + \underbrace{\text{Auth Tag}}_{16\text{ bytes}} = 512\text{ bytes exactly}$$
* **Viewing Key Key Derivation:** Uses the recipient's **Incoming Viewing Key (`ivk`)** with Diffie-Hellman ephemeral key encapsulation ($K = \text{KDF}([esk] \cdot ivk)$) so that only the counterparty can decrypt their confidential execution receipt.

### D. Zero-Leak Confidential Mempool
* Order prices, trade sizes, and directions are **never leaked** to the public API or orderbook.
* The public mempool and UI see only Pallas value commitments ($C$) and hashed intent IDs.
* Only the authorized solver holding the batch execution key decrypts the aggregate curves during the batch clearing window.

### E. Economically Authentic Frequent Batch Auction (FBA)
* **Strict Price Priority:** Inframarginal orders ($P_{\text{buy}} > P^*$ and $P_{\text{sell}} < P^*$) are filled **100%**.
* **Marginal Rationing:** Pro-rata allocation is applied **exclusively to marginal orders** sitting at the boundary price $P^*$.
* **Out-of-the-money orders** receive 0% fill.
* Eliminates latency arbitrage and sandwich attacks completely.

---

## 3. System Architecture

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
                                                   [ v6 Settlement Bundle Builder ]
                                                   - ZIP 228 Action Groups
                                                     [SwapAction + FeeAction]
                                                   - Additive Binding Key: Σ bsk_i
                                                   - Strictly 512B Memo Receipts
                                                                   │
                                                                   ▼
                                                     [ Ironwood Shielded Pool ]
                                                     (Zcash Transaction v6)
```

---

## 4. Verification & Testing

### 1. Running the Rust Cryptographic Engine Tests
```bash
cargo test --manifest-path darkbatch_crypto/Cargo.toml
```
* `test_memo_strictly_512_bytes` - Proves memo buffer is strictly 512 bytes.
* `test_pedersen_homomorphism` - Proves Pallas curve additive homomorphism.
* `test_value_balance_conservation` - Proves value balance and binding key verification.

### 2. Running the Full Python Test Suite
```bash
python -m pytest darkbatch/tests/ -v
```
All 7 unit and end-to-end integration tests pass 100%:
* `test_pedersen_commitment` (Pallas engine)
* `test_strictly_512_byte_encrypted_memo` (strict 512-byte buffer)
* `test_intent_creation_and_signature`
* `test_fba_inframarginal_priority_and_marginal_rationing`
* `test_mev_resistance_and_order_invariance`
* `test_zip228_action_groups_and_v6_bundle`
* `test_full_system_lifecycle` (consensus double-spend rejection, anchor updates, full settlement)

### 3. Running the Persistent CLI
```bash
# View registered wallets
python darkbatch/cli/darkbatch_cli.py wallet list

# Seed realistic sealed liquidity
python darkbatch/cli/darkbatch_cli.py epoch seed

# View sealed mempool (zero-leak view)
python darkbatch/cli/darkbatch_cli.py epoch status

# Solve epoch and mine block
python darkbatch/cli/darkbatch_cli.py epoch clear
```

### 4. Running the Web Terminal
```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` to interact with the live zero-leak terminal, depth chart, and memo receipt decrypter.
