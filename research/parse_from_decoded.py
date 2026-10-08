with open("scratch_decoded.txt", "r", encoding="utf-8") as f:
    text = f.read()

idx = text.find('"rows":[')
print("Find in scratch_decoded:", idx)

if idx != -1:
    array_start = idx + len('"rows":')
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
    print(f"End idx: {end_idx}, length: {end_idx - array_start}")
    import json
    rows_str = text[array_start:end_idx]
    rows = json.loads(rows_str)
    print(f"Parsed {len(rows)} rows from scratch_decoded!")
    with open("zcg_all_decisions.json", "w", encoding="utf-8") as out:
        json.dump(rows, out, indent=2, ensure_ascii=False)
