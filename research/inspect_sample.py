with open("scratch_decoded.txt", "r", encoding="utf-8") as f:
    sample = f.read()

# Let's find matches around 'rejected' or 'approved'
import re

matches = [m.start() for m in re.finditer(r'(approved|rejected)', sample, re.IGNORECASE)]
print(f"Found {len(matches)} matches in sample.")

for i, pos in enumerate(matches[:5]):
    start = max(0, pos - 150)
    end = min(len(sample), pos + 150)
    print(f"--- Match {i+1} ---")
    print(sample[start:end])
