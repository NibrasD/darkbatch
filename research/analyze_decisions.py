import json
from collections import Counter

with open("zcg_all_decisions.json", "r", encoding="utf-8") as f:
    decisions = json.load(f)

print(f"Total decisions: {len(decisions)}")
print("Sample row keys:", list(decisions[0].keys()))
print("Sample row 0:", json.dumps(decisions[0], indent=2))
print("Sample row 1:", json.dumps(decisions[1], indent=2))

outcomes = Counter(d.get("outcome") for d in decisions)
print("\nOutcomes breakdown:")
for k, v in outcomes.items():
    print(f"  {k}: {v} ({v/len(decisions)*100:.1f}%)")

# Date range
dates = [d.get("date") for d in decisions if d.get("date")]
print(f"\nDate range: from {min(dates)} to {max(dates)}")

# Let's inspect recent rejected proposals in 2026 and 2025
recent_rejected = [d for d in decisions if d.get("outcome") == "Rejected"]
print(f"\nTotal Rejected: {len(recent_rejected)}")
print("\nTop 15 Most Recent Rejected Proposals:")
for d in recent_rejected[:15]:
    print(f"[{d.get('date')}] {d.get('subject')} | Submitter: {d.get('detail')} | Process: {d.get('process')} | Link: {d.get('decisionHref')}")

recent_approved = [d for d in decisions if d.get("outcome") == "Approved"]
print(f"\nTotal Approved: {len(recent_approved)}")
print("\nTop 15 Most Recent Approved Proposals:")
for d in recent_approved[:15]:
    print(f"[{d.get('date')}] {d.get('subject')} | Submitter: {d.get('detail')} | Process: {d.get('process')} | Link: {d.get('subjectHref')}")
