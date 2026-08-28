#!/usr/bin/env python3
"""Process_SQL.py

Combined pipeline for SQL Server (MS_SQLDB) audit files:
  Step 1 — Normalize    (fields cleaned, keys classified, descriptions numbered)
  Step 2 — Passthrough  (preserve if/condition/then/else, apply formatting)
  Step 3 — Renumber     (sequential 1.XXXX - MSSQL - numbers)

Outputs:
  {base}-normalized.audit
  {base}-normalized-converted.audit   (final, renumbered in place)
"""

import os
import re
from collections import OrderedDict

# =============================================================================
# CONFIGURATION
# =============================================================================

OUTPUT_DIR = r"C:\PySC"

REAL_KEYS = {
    "type", "description", "info", "reference", "see_also",
    "sql_request", "sql_types", "sql_expect",
    "show_output", "severity",
    "match_all",
}

IGNORED_KEYS = {
    "solution",
    "Impact",
    "Note",
    "Caution",
    "Warning",
    "Important",
    "Example",
    "NOTE",
    "https",
}

SEE_ALSO_REPLACEMENT = "See HTH Policies and Standards"
DESC_PREFIX = "MSSQL"

# =============================================================================
# SHARED HELPERS
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
    return f'"{sentence}."'


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
    return '"NIST 800-53r5|' + " ".join(unique) + '"'


def unquote(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


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
            rest = line[len(indent) + len(key) + len(m.group(3)):]
            padding = max_col - len(indent) - len(key)
            result.append(f"{indent}{key}{' ' * padding}{rest}")
        else:
            result.append(line)
    return result


def normalize_custom_item_indent(content):
    """Re-indent every <custom_item>...</custom_item> block: tags at 0, fields at 2 spaces."""
    lines = content.splitlines()
    result = []
    in_item = False
    for line in lines:
        stripped = line.strip()
        if stripped == '<custom_item>':
            in_item = True
            result.append('<custom_item>')
        elif stripped == '</custom_item>':
            in_item = False
            result.append('</custom_item>')
        elif in_item:
            result.append(('  ' + stripped) if stripped else '')
        else:
            result.append(line)
    return '\n'.join(result) + '\n'


def _persist_key(key, set_name):
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

# =============================================================================
# STEP 1 — NORMALIZE
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


def parse_document(lines):
    document = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if re.match(r'\s*<report\b', line):
            m = re.match(r'\s*<report\s+type:"([^"]+)">', line)
            report_type = m.group(1) if m else "PASSED"
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(r'\s*</report>', lines[i]):
                fm = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if fm:
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = fm.group(1)
                    buf = [fm.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            if i < len(lines):
                i += 1  # skip </report>
            document.append({"type": "report", "report_type": report_type, "fields": fields})
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
                if m:
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


def emit_normalize(document, variables):
    output = []
    rendered_blocks = []
    all_keys = []
    desc_counter = 1
    unknown_keys = set()

    # CIS description pattern: starts with digit(s).digit(s) (e.g. "2.1 Ensure...")
    _cis_desc_re = re.compile(r'^\d+\.\d+')

    for node in document:
        if node["type"] != "custom_item":
            continue

        pairs = []
        for k, v in node["fields"].items():
            if k in IGNORED_KEYS:
                continue
            if k not in REAL_KEYS:
                unknown_keys.add(k)
                continue
            if k == "see_also":
                pairs.append((k, f'"{SEE_ALSO_REPLACEMENT}"'))
            elif k == "info":
                info = normalize_info(v)
                if info:
                    pairs.append((k, info))
            elif k == "reference":
                ref = normalize_reference(v)
                if ref:
                    pairs.append((k, ref))
            elif k == "description":
                clean = v.strip().strip('"')
                if _cis_desc_re.match(clean):
                    # Strip leading CIS number and add MSSQL prefix
                    clean = re.sub(r'^\d+(\.\d+)+\s*', '', clean)
                    new_desc = f'"1.{desc_counter:04d} - {DESC_PREFIX} - {clean}"'
                    pairs.append((k, new_desc))
                    desc_counter += 1
                else:
                    pairs.append((k, v))
            else:
                pairs.append((k, resolve_variables(v, variables)))

        rendered_blocks.append(pairs)
        all_keys.extend(k for k, _ in pairs)

    width = max(len(k) for k in all_keys) if all_keys else 0
    block_idx = 0

    for node in document:
        if node["type"] == "text":
            if not node["text"].lstrip().startswith("#"):
                output.append(resolve_variables(node["text"], variables))
        elif node["type"] == "report":
            output.append(f'<report type:"{node["report_type"]}">')
            desc = node["fields"].get("description", "").strip().strip('"').replace("CIS", "HTH")
            if desc:
                output.append(f'  description : "{desc}"')
            see_also = node["fields"].get("see_also", "")
            if see_also:
                output.append(f'  see_also    : "{SEE_ALSO_REPLACEMENT}"')
            show_out = node["fields"].get("show_output", "")
            if show_out:
                output.append(f'  show_output : {show_out}')
            output.append('</report>')
        elif node["type"] == "custom_item":
            output.append("<custom_item>")
            for k, v in rendered_blocks[block_idx]:
                output.append(f"  {k.ljust(width)} : {v}")
            output.append("</custom_item>")
            block_idx += 1

    return output, unknown_keys


def run_normalize(infile):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-normalized.audit")

    with open(infile, encoding="utf-8") as f:
        lines = f.readlines()

    variables = extract_variables(lines)
    document = parse_document(lines)
    output, unknown_keys = emit_normalize(document, variables)

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
            output, _ = emit_normalize(document, variables)

    item_count = sum(1 for line in output if line.strip() == '<custom_item>')

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(output) + "\n")

    print(f"\nNormalized audit written to:")
    print(f"  {outfile}")
    return outfile, item_count

# =============================================================================
# STEP 2 — PASSTHROUGH / STRUCTURE CLEAN
# =============================================================================
# SQL_POLICY items are already valid for Tenable IO's MS_SQLDB check type.
# This step preserves the full if/condition/then/else structure, counts controls,
# and applies indentation normalization and colon alignment.
# =============================================================================

IF_OPEN      = re.compile(r'^\s*<if>')
IF_CLOSE     = re.compile(r'^\s*</if>')
COND_OPEN    = re.compile(r'^\s*<condition[^>]*>')
COND_CLOSE   = re.compile(r'^\s*</condition>')
THEN_OPEN    = re.compile(r'^\s*<then>')
THEN_CLOSE   = re.compile(r'^\s*</then>')
ELSE_OPEN    = re.compile(r'^\s*<else>')
ELSE_CLOSE   = re.compile(r'^\s*</else>')
ITEM_OPEN    = re.compile(r'^\s*<custom_item>')
ITEM_CLOSE   = re.compile(r'^\s*</custom_item>')
REPORT_OPEN  = re.compile(r'^\s*<report\b')
REPORT_CLOSE = re.compile(r'^\s*</report>')


class SqlPassthrough:
    """Walk normalized content, preserve all structure, and count SQL_POLICY controls."""

    def __init__(self):
        self.output_lines = []
        self.collecting_item = False
        self.item_lines = []
        self.collecting_report = False
        self.report_lines = []
        self.total_controls = 0

    def process_content(self, content):
        for line in content.splitlines():
            self._process_line(line)
        return "\n".join(self.output_lines)

    def _emit(self, line):
        self.output_lines.append(line)

    def _process_line(self, line):
        # Pass if/condition/then/else structural tags through unchanged
        for pat in (IF_OPEN, IF_CLOSE, COND_OPEN, COND_CLOSE,
                    THEN_OPEN, THEN_CLOSE, ELSE_OPEN, ELSE_CLOSE):
            if pat.match(line):
                self._emit(line)
                return

        # Collect and count custom_item blocks
        if ITEM_OPEN.match(line):
            self.collecting_item = True
            self.item_lines = [line]
            return
        if self.collecting_item:
            self.item_lines.append(line)
            if ITEM_CLOSE.match(line):
                self.collecting_item = False
                self.total_controls += 1
                for l in self.item_lines:
                    self._emit(l)
                self.item_lines = []
            return

        # Collect and pass report blocks through unchanged
        if REPORT_OPEN.match(line):
            self.collecting_report = True
            self.report_lines = [line]
            return
        if self.collecting_report:
            self.report_lines.append(line)
            if REPORT_CLOSE.match(line):
                self.collecting_report = False
                for l in self.report_lines:
                    self._emit(l)
                self.report_lines = []
            return

        self._emit(line)


def run_passthrough(infile):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-converted.audit")

    with open(infile, encoding="utf-8") as f:
        content = f.read()

    pt = SqlPassthrough()
    result = pt.process_content(content)

    result = normalize_custom_item_indent(result)
    result = re.sub(r'</custom_item>\s*\n(\s*<custom_item>)', r'</custom_item>\n\n\1', result)
    result_lines = align_colons(result.splitlines())
    result = '\n'.join(result_lines) + '\n'

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(result)

    print(f"\nPassthrough audit written to:")
    print(f"  {outfile}")
    print(f"  SQL_POLICY controls : {pt.total_controls}")
    return outfile, pt.total_controls

# =============================================================================
# STEP 3 — RENUMBER AUDIT DESCRIPTIONS
# =============================================================================

_AUDIT_DESC_RE = re.compile(rf'"1\.\d{{4}} - {re.escape(DESC_PREFIX)} - ')


def run_renumber(infile):
    with open(infile, encoding='utf-8') as f:
        content = f.read()

    counter = 0

    def replacer(m):
        nonlocal counter
        counter += 1
        return f'"1.{counter:04d} - {DESC_PREFIX} - '

    content = _AUDIT_DESC_RE.sub(replacer, content)
    item_count = sum(1 for line in content.splitlines() if line.strip() == '<custom_item>')

    with open(infile, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n  Renumbered descriptions written to:")
    print(f"  {infile}")
    return item_count, counter

# =============================================================================
# MAIN
# =============================================================================

def main():
    infile = input("Enter path to input .audit file: ").strip().strip('"').strip("'")
    if not os.path.isfile(infile):
        print("ERROR: Input file does not exist.")
        return

    with open(infile, encoding='utf-8') as f:
        original_lines = f.readlines()
    original_item_count = sum(1 for line in original_lines if re.match(r'\s*<custom_item>', line))

    print("\n--- Step 1: Normalize ---")
    norm_file, norm_item_count = run_normalize(infile)

    print("\n--- Step 2: Passthrough / Structure Clean ---")
    conv_file, pass_count = run_passthrough(norm_file)

    print("\n--- Step 3: Renumber ---")
    final_item_count, desc_count = run_renumber(conv_file)

    print(f"\n{'='*50}")
    print(f"  Original  <custom_item> blocks : {original_item_count}")
    print(f"  Normalized <custom_item> blocks: {norm_item_count}")
    print(f"  Final     <custom_item> blocks : {final_item_count}")
    print(f"  Numbered descriptions          : {desc_count}")
    if final_item_count == original_item_count:
        print(f"  All {original_item_count} audits preserved.")
    else:
        diff = original_item_count - final_item_count
        print(f"  WARNING: {diff} audit(s) may have been lost.")
    print(f"{'='*50}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
