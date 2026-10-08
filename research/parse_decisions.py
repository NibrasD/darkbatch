import re
import json

file_path = r'C:\Users\User\.gemini\antigravity\brain\90fa2346-a3fa-4c0c-9951-ef2e53442ad0\.system_generated\steps\167\content.md'

with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Let's extract the actual push string
# Notice Next.js escapes strings inside push: self.__next_f.push([1,"..."])
# We can find all chunks with a robust parser
pattern = r'self\.__next_f\.push\(\[1,"(.*?)"\]\)'
# Since dots don't match newlines unless DOTALL, and Next.js flight strings can be escaped:
# Let's write a python parser for self.__next_f.push
pos = 0
chunks = []
while True:
    start = text.find('self.__next_f.push([1,"', pos)
    if start == -1:
        break
    start += len('self.__next_f.push([1,"')
    # find the matching end quote
    # It ends with '"])' where quote is not escaped
    idx = start
    escaped = False
    chunk_str = []
    while idx < len(text):
        c = text[idx]
        if escaped:
            escaped = False
            idx += 1
        elif c == '\\':
            escaped = True
            idx += 1
        elif c == '"':
            if text[idx:idx+3] == '"])':
                break
            idx += 1
        else:
            idx += 1
    chunks.append(text[start:idx])
    pos = idx + 3

print(f"Extracted {len(chunks)} chunks.")

# Let's search inside each chunk for grant data
full_rsc = "".join(chunks)
# Unescape javascript string encoding
try:
    decoded = json.loads('"' + full_rsc.replace('\n', '\\n') + '"')
except Exception as e:
    # manual unescape
    decoded = full_rsc.encode().decode('unicode_escape', errors='ignore')

print(f"Decoded length: {len(decoded)}")

# Let's search for JSON arrays or objects containing proposals
# Let's find patterns like: "title": "...", "status": "...", "amount": "..." or similar keys
sample_keywords = ["title", "status", "decision", "amount", "approved", "rejected", "proposal", "grant"]
for kw in ["decision", "rejected", "approved", "recipient", "total"]:
    print(f"Occurrences of '{kw}': {decoded.lower().count(kw)}")

# Save a decoded sample to scratch to inspect
with open("scratch_decoded.txt", "w", encoding="utf-8") as f:
    f.write(decoded[:50000])

print("Saved first 50k chars to scratch_decoded.txt")
