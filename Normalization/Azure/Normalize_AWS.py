#!/usr/bin/env python3
import os
import re
from collections import OrderedDict

# =============================================================================
# OUTPUT DIRECTORY
# =============================================================================

OUTPUT_DIR = r"C:\PySC"

# =============================================================================
# CONFIGURATION
# =============================================================================

REAL_KEYS = {
    "type", "description", "info", "reference", "see_also",
    "show_output", "severity",
    "expect", "not_expect", "regex", "match_all",
    # Azure-specific keys,
    "json_transform",
    "request",
    "aws_action",
    "days",
    "name",
    "policy_arn",
    "xsl_stmt",
}

IGNORED_KEYS = {"solution",

}

SEE_ALSO_REPLACEMENT = "See HTH Policies and Standards"

# =============================================================================
# HELPERS
# =============================================================================

def resolve_variables(text, variables):
    for k, v in variables.items():
        text = text.replace(f"@{k}@", v)
    return text

def normalize_info(raw):
    if not raw:
        return None
    s = raw.strip()
    s = re.sub(r'^[\'"]+', '', s)
    s = re.sub(r'[\'"]+$', '', s)
    s = re.sub(r'\s+', ' ', s)
    sentence = s.split('.')[0].strip()
    if not sentence:
        return None
    return f"\"{sentence}.\""

def normalize_reference(raw):
    if not raw:
        return None
    flat = re.sub(r"\s+", " ", raw)
    parts = [p.strip() for p in flat.split(",")]
    controls = []
    for p in parts:
        m = re.match(r"^800-53r5\|(.+)$", p)
        if m:
            controls.append(m.group(1))
    if not controls:
        return None
    seen = set()
    unique = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return "\"NIST 800-53r5|" + " ".join(unique) + "\""

# =============================================================================
# PASS 1 — VARIABLE EXTRACTION
# =============================================================================

def extract_variables(lines):
    variables = {}
    current = None
    for line in lines:
        m = re.search(r"<name>(.*?)</name>", line)
        if m:
            current = m.group(1)
            continue
        if current:
            d = re.search(r"<default>(.*?)</default>", line)
            if d:
                variables[current] = d.group(1)
                continue
            if "</variable>" in line:
                current = None
    return variables

# =============================================================================
# PASS 2 — PARSE STRUCTURE
# =============================================================================

def _in_open_quote(buf):
    """Return True if the accumulated value lines have an unclosed quote."""
    combined = "\n".join(buf)
    count = len(re.findall(r'(?<!\\)"', combined))
    return count % 2 == 1


def parse_document(lines):
    document = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if re.match(r'\s*<report\s+type:"PASSED">', line):
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(r"\s*</report>", lines[i]):
                m = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if m and not (key and _in_open_quote(buf)):
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = m.group(1)
                    buf = [m.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            document.append({"type": "report-passed", "fields": fields})
            i += 1  # skip </report>
            continue

        if re.match(r'\s*<report\s+type:"WARNING">', line):
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(r"\s*</report>", lines[i]):
                m = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if m and not (key and _in_open_quote(buf)):
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = m.group(1)
                    buf = [m.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            document.append({"type": "report-warning", "fields": fields})
            i += 1  # skip </report>
            continue

        if re.match(r"\s*(<custom_item>|&lt;custom_item&gt;)", line):
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(
                r"\s*(</custom_item>|&lt;/custom_item&gt;)", lines[i]
            ):
                m = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if m and not (key and _in_open_quote(buf)):
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = m.group(1)
                    buf = [m.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            document.append({"type": "custom_item", "fields": fields})
            i += 1
            continue

        document.append({"type": "text", "text": line})
        i += 1

    return document

# =============================================================================
# PASS 3 — TRANSFORM & EMIT
# =============================================================================

def transform_fields(fields, variables, after_passed, desc_counter, unknown_keys):
    """Apply normalization transforms to a field dict. Returns (pairs, new_desc_counter)."""
    pairs = []
    for k, v in fields.items():
        if k in IGNORED_KEYS:
            continue
        if k not in REAL_KEYS:
            unknown_keys.add(k)
            continue

        if k == "see_also":
            pairs.append((k, f"\"{SEE_ALSO_REPLACEMENT}\""))

        elif k == "info":
            info = normalize_info(v)
            if info:
                pairs.append((k, info))

        elif k == "reference":
            ref = normalize_reference(v)
            if ref:
                pairs.append((k, ref))

        elif k == "description" and after_passed:
            clean = v.strip().strip('"')
            clean = re.sub(r'^\d+(\.\d+)+\s*', '', clean)
            new_desc = f"\"1.{desc_counter:03d} - Azure - {clean}\""
            pairs.append((k, new_desc))
            desc_counter += 1

        else:
            pairs.append((k, resolve_variables(v, variables)))

    return pairs, desc_counter


def emit(document, variables):
    output = []
    rendered_blocks = []
    all_keys = []

    after_passed = False
    desc_counter = 1
    unknown_keys = set()

    # Build rendered blocks
    for node in document:
        if node["type"] not in ("custom_item", "report-warning", "report-passed"):
            continue

        if node["type"] == "report-passed":
            pairs, desc_counter = transform_fields(node["fields"], variables, after_passed, desc_counter, unknown_keys)
            rendered_blocks.append(pairs)
            all_keys.extend(k for k, _ in pairs)
            after_passed = True
            continue

        pairs, desc_counter = transform_fields(
            node["fields"], variables, after_passed, desc_counter, unknown_keys
        )
        rendered_blocks.append(pairs)
        all_keys.extend(k for k, _ in pairs)

    width = max(len(k) for k in all_keys) if all_keys else 0
    block_idx = 0

    # Emit final output
    for node in document:
        if node["type"] == "text":
            if not node["text"].lstrip().startswith("#"):
                output.append(resolve_variables(node["text"], variables))

        elif node["type"] == "report-passed":
            output.append('<report type:"PASSED">')
            for k, v in rendered_blocks[block_idx]:
                output.append(f"  {k.ljust(width)} : {v}")
            output.append("</report>")
            block_idx += 1

        elif node["type"] == "report-warning":
            output.append('<report type:"WARNING">')
            for k, v in rendered_blocks[block_idx]:
                output.append(f"  {k.ljust(width)} : {v}")
            output.append("</report>")
            block_idx += 1

        elif node["type"] == "custom_item":
            output.append("<custom_item>")
            for k, v in rendered_blocks[block_idx]:
                output.append(f"  {k.ljust(width)} : {v}")
            output.append("</custom_item>")
            block_idx += 1

    return output, unknown_keys

# =============================================================================
# POST-PROCESS — ALIGN COLONS
# =============================================================================

def align_colons(lines):
    """Align all key : value separators to the same column across the file."""
    kv_re = re.compile(r'^(\s*)([A-Za-z0-9_]+)(\s+): ')
    max_col = 0
    for line in lines:
        m = kv_re.match(line)
        if m:
            col = len(m.group(1)) + len(m.group(2)) + len(m.group(3))
            if col > max_col:
                max_col = col
    result = []
    for line in lines:
        m = kv_re.match(line)
        if m:
            indent = m.group(1)
            key = m.group(2)
            rest = line[len(indent) + len(key) + len(m.group(3)):]  # ": value..."
            padding = max_col - len(indent) - len(key)
            result.append(f"{indent}{key}{' ' * padding}{rest}")
        else:
            result.append(line)
    return result

# =============================================================================
# MAIN
# =============================================================================

def _persist_key(key, set_name):
    """Add key to the named set in this script file for future runs."""
    script = os.path.abspath(__file__)
    with open(script, encoding="utf-8") as f:
        content = f.read()
    pattern = rf'({set_name}\s*=\s*\{{)(.*?)(\}})'
    m = re.search(pattern, content, flags=re.DOTALL)
    if not m:
        print(f"  Could not find {set_name} — add '{key}' manually.")
        return
    prefix, body, closing = m.group(1), m.group(2), m.group(3)
    stripped = body.rstrip()
    if stripped and not stripped.endswith(','):
        body = stripped + ',\n'
    else:
        body = body.rstrip('\n') + '\n'
    new_block = f'{prefix}{body}    "{key}",\n{closing}'
    new_content = content[:m.start()] + new_block + content[m.end():]
    with open(script, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"  '{key}' added to {set_name} in {os.path.basename(script)}.")


def main():
    infile = input("Enter path to input .audit file: ").strip().strip('"').strip("'")
    if not os.path.isfile(infile):
        print("ERROR: Input file does not exist.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-normalized.audit")

    with open(infile, encoding="utf-8") as f:
        lines = f.readlines()

    variables = extract_variables(lines)
    document = parse_document(lines)
    output, unknown_keys = emit(document, variables)
    output = align_colons(output)

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(output) + "\n")

    print("\nNormalized audit written to:")
    print(f"  {outfile}")

    if unknown_keys:
        print("\nUnrecognized keys found — classify each:")
        reclassified = False
        for k in sorted(unknown_keys):
            while True:
                ans = input(f"  '{k}': (R)eal, (I)gnored, (S)kip? ").strip().upper()
                if ans in ('R', 'I', 'S'):
                    break
            if ans == 'R':
                REAL_KEYS.add(k)
                _persist_key(k, 'REAL_KEYS')
                reclassified = True
            elif ans == 'I':
                IGNORED_KEYS.add(k)
                _persist_key(k, 'IGNORED_KEYS')
                reclassified = True
        if reclassified:
            output, _ = emit(document, variables)
            output = align_colons(output)
            with open(outfile, "w", encoding="utf-8") as f:
                f.write("\n".join(output) + "\n")
            print("\nRe-processed with updated key classifications.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
