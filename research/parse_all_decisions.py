import json

file_path = r'C:\Users\User\.gemini\antigravity\brain\90fa2346-a3fa-4c0c-9951-ef2e53442ad0\.system_generated\steps\167\content.md'

with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

pos = text.find(r'\"rows\":[')
start = pos + len(r'\"rows\":')

# We can find the matching closing bracket ']'
# Since it is inside a JSON string escaped as \", let's handle the depth of brackets
depth = 0
in_quote = False
escape = False
end = -1

for i in range(start, len(text)):
    c = text[i]
    if escape:
        escape = False
        continue
    if c == '\\':
        escape = True
        continue
    # In escaped string, quotes appear as \"
    if c == '"' and text[i-1] == '\\':
        in_quote = not in_quote
        continue
    if not in_quote:
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                end = i + 1
                break

print(f"Start: {start}, End: {end}, Length: {end - start}")
raw_arr = text[start:end]

# Now let's unescape: replace \" with " and \\ with \
# Since it's valid JSON once unescaped:
unescaped = raw_arr.replace(r'\"', '"').replace(r'\\', '\\')

try:
    rows = json.loads(unescaped)
    print(f"Successfully parsed {len(rows)} decision rows!")
    with open("zcg_all_decisions.json", "w", encoding="utf-8") as out:
        json.dump(rows, out, indent=2, ensure_ascii=False)
except Exception as e:
    print("Error parsing json:", e)
    # let's inspect the error
    with open("error_chunk.txt", "w", encoding="utf-8") as out:
        out.write(unescaped[:1000])
