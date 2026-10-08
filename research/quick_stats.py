import json

with open("zcg_all_decisions.json", "r", encoding="utf-8") as f:
    decisions = json.load(f)

with open("zcg_api_grants.json", "r", encoding="utf-8") as f:
    grants_data = json.load(f)
grants = grants_data.get("data", [])

print("=== STATS SUMMARY ===")
print("Total Decisions Recorded:", len(decisions))
print("Total Active/Historical Grants in Ledger:", len(grants))

total_usd_grants = sum(g.get("usd", 0) for g in grants if g.get("usd"))
print(f"Total USD Allocated in Grants Ledger: ${total_usd_grants:,.2f}")

# Categories in grants ledger
cat_funds = {}
for g in grants:
    c = g.get("category", "Unspecified")
    cat_funds[c] = cat_funds.get(c, 0) + (g.get("usd") or 0)

print("\nApproved Grants Funds by Category:")
for c, amt in sorted(cat_funds.items(), key=lambda x: x[1], reverse=True):
    print(f"  {c}: ${amt:,.2f}")

# Look at 2026 rejections count
rej_2026 = [d for d in decisions if d.get("outcome") == "Rejected" and d.get("date", "").startswith("2026")]
app_2026 = [d for d in decisions if d.get("outcome") == "Approved" and d.get("date", "").startswith("2026")]
print(f"\n2026 YTD: Rejected = {len(rej_2026)}, Approved = {len(app_2026)}")
