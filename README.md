# DarkBatch 🛡️⚖️
### Confidential Intent-Based Batch Auction & RFQ Protocol for Shielded Zcash (Ironwood Era)

[![Zcash Protocol](https://img.shields.io/badge/Zcash-NU6.3%20Ironwood-blue.svg)](https://z.cash)
[![Specification](https://img.shields.io/badge/Spec-ZIP--228%20%7C%20ZIP--229%20v6-amber.svg)](https://zips.z.cash/zip-0228)
[![MEV Protection](https://img.shields.io/badge/MEV%20Protection-100%25%20FBA-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## 1. Executive Summary

**DarkBatch** is an institutional-grade, MEV-free exchange primitive engineered for the **Zcash Ironwood shielded ecosystem**. Inspired by the venture success of **Archer Exchange** (4th Place DeFi, Colosseum Cypherpunk) and the mathematical foundations of **Frequent Batch Auctions (FBA)**, DarkBatch solves the single greatest barrier facing shielded ZEC adoption: **private, zero-slippage, front-running-immune liquidity**.

Instead of routing orders through transparent order books or automated market makers where high-frequency bots front-run, sandwich, and leak transaction volumes, DarkBatch allows market participants to sign **off-chain cryptographically sealed limit intents**. In discrete 30-second epochs, an off-chain solver matches supply and demand curves to compute a **single Uniform Clearing Price ($P^*$)**. All matched orders execute simultaneously at $P^*$, and settlement is compiled into a single atomic **Zcash Transaction v6 (ZIP 229 / ZIP 228)** settling directly into the **Ironwood Shielded Pool**.

---

## 2. Key Architectural Innovations

### A. Protocol-Native Alignment with Zcash NU6.3
* **Ironwood Shielded Pool (Block 3,428,143+):** Post-Orchard upgrade. All settlement transactions target the Ironwood pool using **Transaction v6 (ZIP 229)** format.
* **ZIP 228 Swap Bundles & Action Groups:** Every matched Swap Order is modeled as an independent `ActionGroupDescription`.
* **Additive Binding Keys ($bsk$ aggregation):** Under ZIP 228 consensus rules, each participant emits a binding key share $bsk_i$. The solver aggregates these into:
  $$\mathsf{bsk}_{\text{bundle}} = \sum \mathsf{bsk}_i \pmod{q}$$
  proving on-chain value balance conservation without revealing individual trade sizes.
* **512-Byte Encrypted Execution Memos (ZIP 212 / ZIP 302):** Each participant receives an encrypted execution receipt in their shielded output containing the epoch ID, execution price $P^*$, and transaction proof.

### B. Mathematical MEV Immunity (Frequent Batch Auction)
* **Discrete Epochs:** Orders within a batch are treated as simultaneous. Microsecond latency advantages are eliminated.
* **Uniform Clearing Price ($P^*$):** Every matched buyer and seller transacts at the exact same equilibrium price $P^* = \arg\max \min(Q_D(p), Q_S(p))$.
* **Pro-Rata Rationing:** Marginal orders at the boundary are filled proportionally, eliminating priority gas auctions.

---

## 3. System Architecture

```
Trader A (Buyer)  ─── Encrypted Limit Intent ───┐
Trader B (Seller) ─── Encrypted Limit Intent ───┼──> [ DarkBatch Coordinator ]
Trader C (Whale)  ─── Encrypted Limit Intent ───┘             │
                                                              ▼
                                                   [ Batch Solver Engine ]
                                                   - Aggregates Supply & Demand
                                                   - Computes Uniform Price P*
                                                   - Pro-rata rationing for ties
                                                              │
                                                              ▼
                                              [ v6 Settlement Bundle Builder ]
                                              - ZIP 228 Action Groups
                                              - Additive Binding Key: Σ bsk_i
                                              - 512B Encrypted Memo Receipts
                                                              │
                                                              ▼
                                                [ Ironwood Shielded Pool ]
                                                (Zcash Mainnet Settlement)
```

---

## 4. Quickstart & Verification

### Running the Test Suite
DarkBatch includes a comprehensive test suite validating Pedersen commitments, memo cryptography, FBA pricing, and MEV-invariance:
```bash
python -m pytest darkbatch/tests/test_darkbatch.py -v
```

### Starting the Coordinator Server & Interactive Dashboard
```bash
python -m uvicorn darkbatch.api.server:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to `http://127.0.0.1:8000` to interact with the live trading terminal, seed test liquidity, and trigger atomic batch settlements.

---

## 5. Sharia & Venture Compliance
* **Spot Trading Only:** No margin, no leverage, no synthetic derivatives, and no debt-based interest.
* **No Short Selling:** All sell intents represent verifiably committed assets.
* **Immediate Handover (التقابض الفوري):** Handled atomically via instantaneous on-chain bundle execution.
* **Eradicating Exploitation (تلقي الركبان والنجش):** Mechanically prevents front-running and artificial price inflation.
