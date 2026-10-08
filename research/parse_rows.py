import json
import re

file_path = r'C:\Users\User\.gemini\antigravity\brain\90fa2346-a3fa-4c0c-9951-ef2e53442ad0\.system_generated\steps\167\content.md'

with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Locate "rows":[
start_key = '"rows":['
idx = text.find(start_key)
if idx == -1:
    print("Could not find rows:[")
    exit()

# Parse the JSON array starting at idx + len('"rows":')
array_start = idx + len('"rows":')
# Find the matching closing bracket ']' taking into account string escapes
depth = 0
in_str = False
escape = False
end_idx = -1

for i in range(array_start, len(text)):
    c = text[i]
    if escape:
        escape = False
        continue
    if c == '\\':
        escape = True
        continue
    if c == '"':
        in_str = not in_str
        continue
    if not in_str:
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                end_idx = i + 1
                break

json_array_str = text[array_start:end_idx]
print(f"Extracted json array of length: {len(json_array_str)}")

# Next.js escapes inside string: \" -> "
# If json_array_str was inside a JSON string, let's decode it
try:
    rows = json.loads(json_array_str)
except Exception as e:
    # Try unescaping quotes
    unescaped = json_array_str.replace(r'\"', '"').replace(r'\\', '\\')
    rows = json.loads(unescaped)

print(f"Total rows successfully parsed: {len(rows)}")

# Save all parsed rows to a clean json file
with open("zcg_all_decisions.json", "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2, ensure_ascii=False)

print("Saved to zcg_all_decisions.json")
