
#!/usr/bin/env python3
import os
import re
from collections import OrderedDict

# =============================================================================
# OUTPUT DIRECTORY
# =============================================================================

OUTPUT_DIR = r"C:\PySC\Normalization"

# =============================================================================
# CONFIGURATION
# =============================================================================

REAL_KEYS = {
    "type", "description", "info", "reference", "see_also", "solution",
    "api_request_type", "request", "xsl_stmt", "not_expect", "show_output",
    "powershell_args", "key_item",
    "value_type", "value_data", "reg_key", "reg_item", "reg_option",
    "audit_policy_subcategory", "right_type", "reg_include_hku_users",
    "check_type", "account_type", "password_policy", "lockout_policy",
    "regex", "expect", "severity",
    "wmi_key",
    "wmi_namespace",
    "wmi_request",
    "wmi_attribute",
}

IGNORED_KEYS = {
    "Impact",
    "Note",
    "4944",
    "4945",
    "4946",
    "4947",
    "4948",
    "4949",
    "4950",
    "4951",
    "4952",
    "4953",
    "4954",
    "4956",
    "4957",
    "4958",
    "5063",
    "5064",
    "5065",
    "5066",
    "5067",
    "5068",
    "5069",
    "5070",
    "6145",
    "Caution",
    "Disabled",
    "Enabled",
    "Important",
    "Warning",
    "Example",
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
def parse_document(lines):
    document = []
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()

        # ============================================================
        # PASSED REPORT
        # ============================================================
        if re.match(r'\s*<report\s+type:"PASSED">', line):
            fields = OrderedDict()
            key = None
            buf = []

            i += 1

            while i < len(lines) and not re.match(r"\s*</report>", lines[i]):

                m = re.match(r"^\s{6,}([A-Za-z0-9_]+)\s*:\s*(.*)$", lines[i])

                if m:
                    possible_key = m.group(1)

                    if possible_key in REAL_KEYS or possible_key in IGNORED_KEYS:

                        if key:
                            fields[key] = "\n".join(buf).strip()

                            # if key == "solution":
                            #     print("\nPARSED SOLUTION:")
                            #     print(repr(fields[key]))

                        key = possible_key
                        buf = [m.group(2)]

                    elif key:
                        buf.append(lines[i].rstrip())

                elif key:
                    buf.append(lines[i].rstrip())

                i += 1

            if key:
                fields[key] = "\n".join(buf).strip()

                # if key == "solution":
                #     print("\nPARSED SOLUTION:")
                #     print(repr(fields[key]))

            document.append({
                "type": "report-passed",
                "fields": fields
            })

            i += 1
            continue

        # ============================================================
        # WARNING REPORT
        # ============================================================
        if re.match(r'\s*<report\s+type:"WARNING">', line):
            fields = OrderedDict()
            key = None
            buf = []

            i += 1

            while i < len(lines) and not re.match(r"\s*</report>", lines[i]):

                m = re.match(r"^\s{6,}([A-Za-z0-9_]+)\s*:\s*(.*)$", lines[i])

                if m:
                    possible_key = m.group(1)

                    if possible_key in REAL_KEYS or possible_key in IGNORED_KEYS:

                        if key:
                            fields[key] = "\n".join(buf).strip()

                            # if key == "solution":
                            #     print("\nPARSED SOLUTION:")
                            #     print(repr(fields[key]))

                        key = possible_key
                        buf = [m.group(2)]

                    elif key:
                        buf.append(lines[i].rstrip())

                elif key:
                    buf.append(lines[i].rstrip())

                i += 1

            if key:
                fields[key] = "\n".join(buf).strip()

                # if key == "solution":
                #     print("\nPARSED SOLUTION:")
                #     print(repr(fields[key]))

            document.append({
                "type": "report-warning",
                "fields": fields
            })

            i += 1
            continue

        # ============================================================
        # CUSTOM ITEM
        # ============================================================
        if re.match(r"\s*<custom_item>", line):
            fields = OrderedDict()
            key = None
            buf = []

            i += 1

            while i < len(lines) and not re.match(
                r"\s*</custom_item>", lines[i]
            ):

                m = re.match(r"^\s{6,}([A-Za-z0-9_]+)\s*:\s*(.*)$", lines[i])

                if m:
                    possible_key = m.group(1)

                    if possible_key in REAL_KEYS or possible_key in IGNORED_KEYS:

                        if key:
                            fields[key] = "\n".join(buf).strip()

                            # if key == "solution":
                            #     print("\nPARSED SOLUTION:")
                            #     print(repr(fields[key]))

                        key = possible_key
                        buf = [m.group(2)]

                    elif key:
                        buf.append(lines[i].rstrip())

                elif key:
                    buf.append(lines[i].rstrip())

                i += 1

            if key:
                fields[key] = "\n".join(buf).strip()

                # if key == "solution":
                #     print("\nPARSED SOLUTION:")
                #     print(repr(fields[key]))

            document.append({
                "type": "custom_item",
                "fields": fields
            })

            i += 1
            continue

        # ============================================================
        # NORMAL TEXT
        # ============================================================
        document.append({
            "type": "text",
            "text": line
        })

        i += 1

    return document

# =============================================================================
# PASS 3 — TRANSFORM & EMIT (FIXED & STABLE)
# =============================================================================

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
            pairs = []
            # if "solution" in node["fields"]:
            #     print("\nSOLUTION VALUE:")
            #     print(repr(node["fields"]["solution"]))

            for k, v in node["fields"].items():
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
                else:
                    pairs.append((k, resolve_variables(v, variables)))
            rendered_blocks.append(pairs)
            all_keys.extend(k for k, _ in pairs)
            after_passed = True
            continue

        pairs = []

        for k, v in node["fields"].items():
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
                new_desc = f"\"1.{desc_counter:04d} - MSSRV - {clean}\""
                pairs.append((k, new_desc))
                desc_counter += 1

            else:
                pairs.append((k, resolve_variables(v, variables)))

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
            continue

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
# MAIN
# =============================================================================

def _persist_key(key, set_name):
    """Add key to the named set in this script file for future runs."""
    script = os.path.abspath(__file__)
    with open(script, encoding="utf-8") as f:
        content = f.read()
    # Find the set block and insert the new key before the closing }
    pattern = rf'({set_name}\s*=\s*\{{)(.*?)(\}})'
    m = re.search(pattern, content, flags=re.DOTALL)
    if not m:
        print(f"  Could not find {set_name} — add '{key}' manually.")
        return
    prefix, body, closing = m.group(1), m.group(2), m.group(3)
    # Ensure trailing comma on last entry
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


# =============================================================================
# MAIN
# =============================================================================

def _persist_key(key, set_name):
    """Add key to the named set in this script file for future runs."""
    script = os.path.abspath(__file__)
    with open(script, encoding="utf-8") as f:
        content = f.read()
    # Find the set block and insert the new key before the closing }
    pattern = rf'({set_name}\s*=\s*\{{)(.*?)(\}})'
    m = re.search(pattern, content, flags=re.DOTALL)
    if not m:
        print(f"  Could not find {set_name} — add '{key}' manually.")
        return
    prefix, body, closing = m.group(1), m.group(2), m.group(3)
    # Ensure trailing comma on last entry
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

def process_file(infile):
    if not os.path.isfile(infile):
        print(f"ERROR: Input file does not exist: {infile}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-normalized.audit")

    with open(infile, encoding="utf-8") as f:
        lines = f.readlines()

    variables = extract_variables(lines)
    document = parse_document(lines)
    output, unknown_keys = emit(document, variables)

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

            with open(outfile, "w", encoding="utf-8") as f:
                f.write("\n".join(output) + "\n")

            print("\nRe-processed with updated key classifications.")

def process_folder(folder):
    audit_files = sorted(
        f for f in os.listdir(folder)
        if f.lower().endswith(".audit")
    )

    if not audit_files:
        print("No .audit files found.")
        return

    print(f"\nFound {len(audit_files)} audit files.\n")

    for fname in audit_files:
        infile = os.path.join(folder, fname)

        print("-" * 60)
        print(f"Processing: {fname}")

        process_file(infile)

def main():
    path = input(
        "Enter .audit file path OR folder path: "
    ).strip().strip('"').strip("'")

    if os.path.isdir(path):
        process_folder(path)

    elif os.path.isfile(path):
        process_file(path)

    else:
        print("ERROR: Path does not exist.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()

