import json
import re
import sys
from collections import defaultdict

# Force stdout to utf-8
sys.stdout.reconfigure(encoding='utf-8')

with open("zcg_all_decisions.json", "r", encoding="utf-8") as f:
    decisions = json.load(f)

rejected = [d for d in decisions if d.get("outcome") == "Rejected"]
approved = [d for d in decisions if d.get("outcome") == "Approved"]

print(f"Total Rejected: {len(rejected)}")
print(f"Total Approved: {len(approved)}")

categories = {
    "Ambassadors / Marketing / Content / Events / Meetups": [
        r"\bambassador\b", r"\bpodcast\b", r"\bvideo\b", r"\bmarketing\b", r"\bcommunity\b", 
        r"\bcampaign\b", r"\btwitter\b", r"\bcontent\b", r"\bevent\b", r"\bconference\b", 
        r"\bmeetup\b", r"\bswag\b", r"\bfilm\b", r"\bdocumentary\b", r"\bmedia\b", r"\bmerchandise\b", r"\bsponsorship\b"
    ],
    "Fiat Ramps / P2P / POS / Merchant Payments": [
        r"\bramp\b", r"\bfiat\b", r"\bp2p\b", r"\bexchange\b", r"\bremittance\b", 
        r"\batm\b", r"\bcard\b", r"\bpos\b", r"\bmerchant\b", r"\bpayment gateway\b", r"\bcheckout\b"
    ],
    "Wallets / Mobile / Recovery / Key Management": [
        r"\bwallet\b", r"\bseed\b", r"\brecovery\b", r"\bmobile\b", r"\bios\b", 
        r"\bandroid\b", r"\bsigner\b", r"\bhardware\b", r"\bledger\b", r"\bkeystore\b", r"\bui\b", r"\bgui\b"
    ],
    "DeFi / Bridges / Swaps / Liquidity / L2": [
        r"\bdex\b", r"\bswap\b", r"\bbridge\b", r"\bdefi\b", r"\bamm\b", 
        r"\bliquidity\b", r"\bl2\b", r"\brollup\b", r"\bcross-chain\b", r"\batomic\b", r"\bwrapped\b"
    ],
    "Accounting / Audit / Tax / Payroll / Selective Receipts": [
        r"\baccounting\b", r"\baudit\b", r"\breceipt\b", r"\btax\b", r"\bpayroll\b", 
        r"\binvoice\b", r"\bbookkeeping\b", r"\bdisclosure\b", r"\bviewing key\b"
    ],
    "Identity / Auth / Reputation / KYC / Credential": [
        r"\bidentity\b", r"\bauth\b", r"\bkyc\b", r"\bcredential\b", r"\bdid\b", 
        r"\breputation\b", r"\blogin\b", r"\bsign-in\b", r"\bverification\b"
    ],
    "Smart Contracts / NFTs / Inscriptions / Web3 / Gaming": [
        r"\bnft\b", r"\btoken\b", r"\bcontract\b", r"\bsmart contract\b", r"\bweb3\b", 
        r"\bgame\b", r"\bgaming\b", r"\bmetaverse\b", r"\bdao\b"
    ],
    "Node / Mining / Infrastructure / Zebra / Lightwalletd": [
        r"\bmining\b", r"\bminer\b", r"\bzebra\b", r"\bpool\b", r"\bnode\b", 
        r"\bzcashd\b", r"\blightwalletd\b", r"\brpc\b", r"\binfrastructure\b", r"\bdev tool\b", r"\bsdk\b", r"\blibrary\b"
    ],
    "Cryptography / ZK Research / Formal Verification / Core ZIPs": [
        r"\bcrypto\b", r"\bzk\b", r"\bzero-knowledge\b", r"\bsnark\b", r"\bstark\b", 
        r"\bhalo\b", r"\bcurve\b", r"\bformal\b", r"\bproof\b", r"\bcircuit\b", r"\bironwood\b", r"\bfrost\b", r"\bzip\b"
    ],
    "AI / Autonomous Agents / Machine Payments": [
        r"\bai\b", r"\bagent\b", r"\b402\b", r"\bllm\b", r"\bbot\b", r"\bmachine payments\b"
    ]
}

def classify(items):
    res = defaultdict(list)
    for d in items:
        subj = d.get("subject", "").lower()
        matched = False
        for cat, patterns in categories.items():
            if any(re.search(pat, subj) for pat in patterns):
                res[cat].append(d)
                matched = True
                break
        if not matched:
            res["Other / Niche"].append(d)
    return res

cat_rej = classify(rejected)
cat_app = classify(approved)

print("\n================== REJECTED PROPOSALS (347 TOTAL) ==================")
for cat, items in sorted(cat_rej.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n[{cat}]: {len(items)} proposals ({len(items)/len(rejected)*100:.1f}%)")
    for item in items[:5]:
        print(f"  * [{item.get('date')}] {item.get('subject')} (Submitter: {item.get('detail')})")

print("\n================== APPROVED PROPOSALS (183 TOTAL) ==================")
for cat, items in sorted(cat_app.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n[{cat}]: {len(items)} proposals ({len(items)/len(approved)*100:.1f}%)")
    for item in items[:5]:
        print(f"  * [{item.get('date')}] {item.get('subject')} (Submitter: {item.get('detail')})")
