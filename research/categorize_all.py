import json
from collections import defaultdict

with open("zcg_all_decisions.json", "r", encoding="utf-8") as f:
    decisions = json.load(f)

rejected = [d for d in decisions if d.get("outcome") == "Rejected"]
approved = [d for d in decisions if d.get("outcome") == "Approved"]

print(f"Total Rejected: {len(rejected)}")
print(f"Total Approved: {len(approved)}")

# Categorize rejected proposals by keywords in subject
categories = {
    "Ambassadors / Marketing / Content / Social / Podcasts": ["ambassador", "podcast", "video", "marketing", "community", "campaign", "twitter", "content", "event", "conference", "meetup", "swag", "film", "documentary"],
    "Fiat Ramps / P2P / Remittance": ["ramp", "fiat", "p2p", "exchange", "remittance", "atm", "card", "pay"],
    "Wallets / Mobile / Recovery / Seed": ["wallet", "seed", "recovery", "mobile", "ios", "android", "signer", "hardware", "ledger"],
    "DeFi / DEX / Swaps / Bridges / L2": ["dex", "swap", "bridge", "defi", "amm", "liquidity", "l2", "rollup", "cross-chain", "atomic"],
    "AI / Autonomous Agents / Bots": ["ai", "agent", "bot", "machine", "402", "llm"],
    "Accounting / Audit / Receipts / Taxes": ["accounting", "audit", "receipt", "tax", "payroll", "invoice", "bookkeeping"],
    "Identity / Auth / Reputation / KYC": ["identity", "auth", "kyc", "credential", "did", "reputation", "login"],
    "Smart Contracts / NFTs / Tokens on L1": ["nft", "token", "contract", "smart contract", "ordinals", "inscriptions"],
    "Mining / Nodes / Low-level Infrastructure": ["mining", "miner", "zebra", "pool", "node", "zcashd", "lightwalletd", "network", "rpc"],
    "Cryptography / Research / Formal Verification": ["crypto", "zk", "zero-knowledge", "snark", "stark", "halo", "curve", "formal", "proof", "circuit"]
}

cat_rejected = defaultdict(list)
for d in rejected:
    subj = d.get("subject", "").lower()
    matched = False
    for cat, kws in categories.items():
        if any(kw in subj for kw in kws):
            cat_rejected[cat].append(d)
            matched = True
            break
    if not matched:
        cat_rejected["Other / Uncategorized"].append(d)

print("\n--- REJECTED BREAKDOWN BY CATEGORY ---")
for cat, items in sorted(cat_rejected.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n{cat}: {len(items)} ({len(items)/len(rejected)*100:.1f}%)")
    for item in items[:4]:
        print(f"  - [{item.get('date')}] {item.get('subject')} ({item.get('detail')})")

cat_approved = defaultdict(list)
for d in approved:
    subj = d.get("subject", "").lower()
    matched = False
    for cat, kws in categories.items():
        if any(kw in subj for kw in kws):
            cat_approved[cat].append(d)
            matched = True
            break
    if not matched:
        cat_approved["Other / Uncategorized"].append(d)

print("\n\n--- APPROVED BREAKDOWN BY CATEGORY ---")
for cat, items in sorted(cat_approved.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n{cat}: {len(items)} ({len(items)/len(approved)*100:.1f}%)")
    for item in items[:4]:
        print(f"  - [{item.get('date')}] {item.get('subject')} ({item.get('detail')})")
