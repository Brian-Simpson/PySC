
#!/usr/bin/env python3
"""
This script is essentially an Audit File Normalizer and Standardizer for Nessus/Tenable .audit files.
This focuses on cleaning, restructuring, normalizing, and standardizing the contents of individual audit files.
Its goal is to create a consistent Tenable parsable audit format suitable for enterprise use,
converting vendor/CIS/STIG-generated audits into an internally standardized audit baseline.

High-Level Workflow
For each .audit file:

Extract variable definitions.
Parse the audit structure.
Identify report and custom-item blocks.
Normalize descriptions, references, and info fields.
Replace variables with actual values.
Remove unwanted fields.
Renumber descriptions.
Standardize formatting.
Write a new -normalized.audit file.
Learn previously unknown key field names and update itself for future runs.
"""
import os
import re
import sys
from collections import OrderedDict
import json
import csv

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..").replace("\\", "/")
)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from pysc_block_parser import extract_variables, parse_document

try:
    import openpyxl
    from openpyxl import Workbook
except Exception:
    openpyxl = None
    Workbook = None


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
    "f5_command",
    "item",
    "json_transform",
    "match_all",
    "sql_expect",
    "sql_request",
    "sql_types",
    "cmd",
    "file",
    "file_required",
    "group",
    "is_substring",
    "mask",
    "min_occurrences",
    "operator",
    "owner",
    "required",
    "rpm",
    "string_required",
    "timeout",
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
    "MinimumPasswordLength",
    "PasswordReusePrevention",
    "aws_action",
    "NOTE",
    "content",
    "context",
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


def normalize_description(raw):
    if not raw:
        return None
    s = raw.strip()
    s = s.strip('"')
    s = re.sub(r"^\d+(\.\d+)+\s*", "", s)
    s = re.sub(r"'([^']+)'", r"\1", s)
    s = re.sub(r"\s+", " ", s).strip()
    return f'"{s}"'


# -----------------------------------------------------------------------------
# Catalog / Excel export helpers (embedded from tools/catalog_controls.py)
# -----------------------------------------------------------------------------

FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
PLATFORM_RE = re.compile(r"\b([A-Z]{2,6})\b")


def parse_custom_items(text):
    items = []
    parts = re.split(r"<custom_item>|</custom_item>", text, flags=re.IGNORECASE)
    for i in range(1, len(parts), 2):
        body = parts[i]
        fields = {}
        for line in body.splitlines():
            m = FIELD_RE.match(line)
            if m:
                key = m.group(1).lower()
                val = m.group(2).strip()
                fields[key] = val
        items.append(fields)
    return items


def detect_platform(description):
    if not description:
        return 'UNKNOWN'
    d = description.strip().strip('"').strip("'")
    m = re.search(r"-\s*([A-Z]{2,6})\s*-", d)
    if m:
        return m.group(1)
    m2 = PLATFORM_RE.search(d)
    if m2:
        return m2.group(1)
    return 'UNKNOWN'


def determine_platform_from_filename(path):
    name = os.path.basename(path).lower()
    # New rules: 'vmware' -> VMware, 'enterprise' + linux/rhel -> RHEL
    if 'vmware' in name:
        return 'VMware'
    if 'enterprise' in name and ('linux' in name or 'rhel' in name):
        return 'RHEL'
    if 'enterprise' in name:
        return 'MSWRK'
    if 'sql' in name:
        return 'SQL'
    if 'server' in name and 'sql' not in name:
        return 'MSSRV'
    if 'ios' in name:
        return 'IOS'
    if 'palo alto' in name or ('palo' in name and 'alto' in name):
        return 'PAFW'
    if 'nx' in name:
        return 'NX-OS'
    if 'f5' in name:
        return 'F5'
    if 'azure' in name:
        return 'MSAZ'
    if 'amazon' in name or 'aws' in name:
        return 'Amazon'
    return 'UNKNOWN'


def extract_controls_with_context(text):
    results = []
    for if_block in re.findall(r"<if>(.*?)</if>", text, flags=re.DOTALL | re.IGNORECASE):
        cond_type = ''
        mtype = re.search(r"type\s*:\s*\"([^\"]+)\"", if_block, flags=re.IGNORECASE)
        if mtype:
            cond_type = mtype.group(1)

        report_fields = {}
        mreport = re.search(r"<report[^>]*>(.*?)</report>", if_block, flags=re.DOTALL | re.IGNORECASE)
        if mreport:
            for line in mreport.group(1).splitlines():
                fm = FIELD_RE.match(line)
                if fm:
                    report_fields[fm.group(1).lower()] = fm.group(2).strip()

        mcond = re.search(r"<condition[^>]*>(.*?)</condition>", if_block, flags=re.DOTALL | re.IGNORECASE)
        cond_body = mcond.group(1) if mcond else if_block
        items = parse_custom_items(cond_body)
        for it in items:
            results.append((it, cond_type or "", report_fields))

    text_no_if = re.sub(r"<if>.*?</if>", "", text, flags=re.DOTALL | re.IGNORECASE)
    top_items = parse_custom_items(text_no_if)
    for it in top_items:
        results.append((it, "", {}))
    return results


def _sanitize_for_excel(v):
    if v is None:
        return ''
    if not isinstance(v, str):
        v = str(v)
    return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', v)


def generate_catalog(input_folder, output_file=None):
    records_by_platform = {}
    files = []
    for root, _, filenames in os.walk(input_folder):
        for f in filenames:
            if f.lower().endswith('.audit'):
                files.append(os.path.join(root, f))

    for path in sorted(files):
        with open(path, encoding='utf-8') as fh:
            txt = fh.read()
        entries = extract_controls_with_context(txt)
        for it, cond_type, report_fields in entries:
            desc = it.get('description', '')
            # prefer filename-based platform detection
            plat = determine_platform_from_filename(path) or detect_platform(desc)
            rec = {
                'source_file': os.path.relpath(path),
                'control_type': it.get('type', ''),
                'description': desc,
                'info': it.get('info', ''),
                'reference': it.get('reference', ''),
                'raw_fields': json.dumps(it, ensure_ascii=False),
                'condition_type': cond_type,
                'report_type': report_fields.get('type', ''),
                'report_description': report_fields.get('description', ''),
            }
            records_by_platform.setdefault(plat, []).append(rec)

    # Deduplicate records by (control_type, description) per platform
    deduped_by_platform = {}
    for plat, rows in records_by_platform.items():
        seen = {}
        for r in rows:
            key = ((r.get('control_type') or '').strip().lower(), (r.get('description') or '').strip().lower())
            if key not in seen:
                seen[key] = {
                    'control_type': r.get('control_type', ''),
                    'description': r.get('description', ''),
                    'info': r.get('info', ''),
                    'reference': r.get('reference', ''),
                    'raw_fields': r.get('raw_fields', ''),
                    'condition_type': r.get('condition_type', ''),
                    'report_type': r.get('report_type', ''),
                    'report_description': r.get('report_description', ''),
                    'source_files': [r.get('source_file')] if r.get('source_file') else [],
                }
            else:
                if r.get('source_file'):
                    seen[key]['source_files'].append(r.get('source_file'))
                if not seen[key]['info'] and r.get('info'):
                    seen[key]['info'] = r.get('info')
                if not seen[key]['reference'] and r.get('reference'):
                    seen[key]['reference'] = r.get('reference')
                if not seen[key]['raw_fields'] and r.get('raw_fields'):
                    seen[key]['raw_fields'] = r.get('raw_fields')
        out_rows = []
        for v in seen.values():
            v['source_count'] = len(sorted(set(v['source_files'])))
            v['source_files'] = ';'.join(sorted(set(v['source_files'])))
            out_rows.append(v)
        deduped_by_platform[plat] = out_rows

    if output_file:
        outpath = output_file
    else:
        normalized_dir = os.path.join(input_folder, 'Normalized')
        os.makedirs(normalized_dir, exist_ok=True)
        outpath = os.path.join(normalized_dir, 'controls_catalog.xlsx')

    if Workbook is None:
        raise RuntimeError('openpyxl is required to write Excel workbook; pip install openpyxl')
    wb = Workbook()
    wb.remove(wb.active)
    for plat, rows in sorted(deduped_by_platform.items()):
        safe_name = plat[:31]
        ws = wb.create_sheet(title=safe_name)
        all_keys = set()
        for r in rows:
            all_keys.update(r.keys())
        meta_keys = [
            'control_type', 'description', 'info', 'reference', 'condition_type',
            'report_type', 'report_description', 'raw_fields', 'source_count',
            'source_files', 'source_file'
        ]
        headers = [k for k in meta_keys if k in all_keys]
        headers += sorted(k for k in all_keys if k not in headers)
        ws.append(headers)
        for r in rows:
            ws.append([_sanitize_for_excel(r.get(h, '')) for h in headers])
    temp_outpath = outpath + '.tmp'
    wb.save(temp_outpath)
    try:
        os.replace(temp_outpath, outpath)
        final_outpath = outpath
    except PermissionError:
        fallback_outpath = outpath.replace('.xlsx', '.new.xlsx')
        os.replace(temp_outpath, fallback_outpath)
        print(f"Could not replace locked workbook '{outpath}'. Written to '{fallback_outpath}' instead.")
        final_outpath = fallback_outpath
    print(f'Wrote workbook: {final_outpath}')
    return final_outpath


def find_duplicates_in_workbook(wb_path):
    if openpyxl is None:
        raise RuntimeError('openpyxl is required; pip install openpyxl')
    wb = openpyxl.load_workbook(wb_path, read_only=True)
    out = {}

    def _norm(s):
        if s is None:
            return ''
        s = str(s).strip().strip('"').strip("'")
        s = re.sub(r'\s+', ' ', s)
        return s.lower()

    for name in wb.sheetnames:
        ws = wb[name]
        rows = ws.iter_rows(values_only=True)
        try:
            headers = next(rows)
        except StopIteration:
            out[name] = []
            continue
        hidx = { (h.lower() if h else ''): i for i, h in enumerate(headers) }
        desc_i = hidx.get('description')
        type_i = hidx.get('control_type')
        src_i = hidx.get('source_file')
        counts = {}
        for r in rows:
            desc = _norm(r[desc_i]) if desc_i is not None and desc_i < len(r) else ''
            ctype = _norm(r[type_i]) if type_i is not None and type_i < len(r) else ''
            src = r[src_i] if src_i is not None and src_i < len(r) else ''
            key = (ctype, desc)
            counts.setdefault(key, []).append(src)
        dups = [
            {'control_type': k[0], 'description': k[1], 'count': len(v), 'examples': v[:5]}
            for k, v in counts.items() if len(v) > 1
        ]
        out[name] = sorted(dups, key=lambda x: -x['count'])
    return out


def export_duplicates_csvs(wb_path, out_dir=None):
    if openpyxl is None:
        raise RuntimeError('openpyxl is required; pip install openpyxl')
    if out_dir is None:
        out_dir = os.path.dirname(wb_path)
    wb = openpyxl.load_workbook(wb_path, read_only=True)

    def _norm(s):
        if s is None:
            return ''
        s = str(s).strip().strip('"').strip("'")
        s = re.sub(r'\s+', ' ', s)
        return s

    written = []
    for name in wb.sheetnames:
        ws = wb[name]
        rows = ws.iter_rows(values_only=True)
        try:
            headers = [h.lower() if h else '' for h in next(rows)]
        except StopIteration:
            continue
        hidx = {h: i for i, h in enumerate(headers)}
        desc_i = hidx.get('description')
        type_i = hidx.get('control_type')
        src_i = hidx.get('source_file')
        info_i = hidx.get('info')
        ref_i = hidx.get('reference')
        see_i = hidx.get('see_also')
        show_i = hidx.get('show_output')
        cond_i = hidx.get('condition_type') or hidx.get('condition')
        rpt_type_i = hidx.get('report_type')
        rpt_desc_i = hidx.get('report_description')
        raw_i = hidx.get('raw_fields')

        counts = {}
        rows_list = list(rows)
        for r in rows_list:
            desc = _norm(r[desc_i]) if desc_i is not None and desc_i < len(r) else ''
            ctype = _norm(r[type_i]) if type_i is not None and type_i < len(r) else ''
            key = (ctype.lower(), desc.lower())
            counts.setdefault(key, []).append(r)

        duplicates = {k: v for k, v in counts.items() if len(v) > 1}
        if not duplicates:
            continue

        out_csv = os.path.join(out_dir, f'duplicates_{name}.csv')
        with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            hdr = ['sheet','control_type','description','info','reference','see_also','show_output','condition_type','report_type','report_description','raw_fields','count','examples']
            writer.writerow(hdr)
            for (ctype, desc), rows_list in sorted(duplicates.items(), key=lambda x: -len(x[1])):
                first = rows_list[0]
                info = first[info_i] if info_i is not None and info_i < len(first) else ''
                ref = first[ref_i] if ref_i is not None and ref_i < len(first) else ''
                see = first[see_i] if see_i is not None and see_i < len(first) else ''
                show = first[show_i] if show_i is not None and show_i < len(first) else ''
                cond = first[cond_i] if cond_i is not None and cond_i < len(first) else ''
                rpt_type = first[rpt_type_i] if rpt_type_i is not None and rpt_type_i < len(first) else ''
                rpt_desc = first[rpt_desc_i] if rpt_desc_i is not None and rpt_desc_i < len(first) else ''
                raw = first[raw_i] if raw_i is not None and raw_i < len(first) else ''
                examples = []
                for r in rows_list[:10]:
                    src = r[src_i] if src_i is not None and src_i < len(r) else ''
                    examples.append(src)
                writer.writerow([name, ctype, desc, info, ref, see, show, cond, rpt_type, rpt_desc, raw, len(rows_list), ';'.join(examples)])

        written.append(out_csv)
    return written

# =============================================================================
# PASS 1 — VARIABLE EXTRACTION
# =============================================================================

# WARNING: extract_variables and parse_document are imported from pysc_block_parser.
# They are intentionally left out of this module to prevent duplicated parsing logic.


# =============================================================================
# PASS 2 — PARSE STRUCTURE
# =============================================================================

# WARNING: parse_document is imported from pysc_block_parser.

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
                desc = normalize_description(v)
                pairs.append((k, desc))

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

    base = os.path.splitext(os.path.basename(infile))[0]

    input_folder = os.path.dirname(infile)
    normalized_folder = os.path.join(input_folder, "Normalized")
    os.makedirs(normalized_folder, exist_ok=True)

    outfile = os.path.join(
        normalized_folder,
        f"{base}.audit"
    )

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

def parse_cli_args():
    input_arg = None
    out_arg = None
    catalog_flag = False
    export_duplicates = False
    skip_next = False

    for i, arg in enumerate(sys.argv[1:]):
        if skip_next:
            skip_next = False
            continue
        if arg == '--catalog':
            catalog_flag = True
        elif arg == '--export-duplicates':
            export_duplicates = True
        elif arg.startswith('-'):
            continue
        elif input_arg is None:
            input_arg = arg
        elif out_arg is None:
            out_arg = arg

    return input_arg, out_arg, catalog_flag, export_duplicates


def main():
    input_arg, out_arg, catalog_flag, export_duplicates = parse_cli_args()

    if input_arg:
        input_arg = input_arg.strip().strip('"').strip("'")
        if os.path.isdir(input_arg):
            process_folder(input_arg)
            # auto-generate catalog for folder runs
            print('\nGenerating controls catalog...')
            outp = generate_catalog(input_arg, out_arg)
            if export_duplicates:
                csvs = export_duplicates_csvs(outp)
                for p in csvs:
                    print(f'Wrote {p}')
            return
        elif os.path.isfile(input_arg):
            process_file(input_arg)
            if catalog_flag:
                folder = os.path.dirname(input_arg)
                print('\nGenerating controls catalog...')
                outp = generate_catalog(folder, out_arg)
                if export_duplicates:
                    csvs = export_duplicates_csvs(outp)
                    for p in csvs:
                        print(f'Wrote {p}')
            return
        else:
            print('ERROR: Path does not exist.')
            return

    path = input(
        'Enter .audit file path OR folder path: '
    ).strip().strip('"').strip("'")

    if os.path.isdir(path):
        process_folder(path)
        print('\nGenerating controls catalog...')
        outp = generate_catalog(path, out_arg)
        if export_duplicates:
            csvs = export_duplicates_csvs(outp)
            for p in csvs:
                print(f'Wrote {p}')

    elif os.path.isfile(path):
        process_file(path)
        if catalog_flag:
            folder = os.path.dirname(path)
            print('\nGenerating controls catalog...')
            outp = generate_catalog(folder, out_arg)
            if export_duplicates:
                csvs = export_duplicates_csvs(outp)
                for p in csvs:
                    print(f'Wrote {p}')

    else:
        print('ERROR: Path does not exist.')

if __name__ == "__main__":
    try:
        if '--catalog' in sys.argv:
            # usage: python Normalize_Windows_AUDITS.py --catalog [input_folder] [output_file]
            idx = sys.argv.index('--catalog')
            input_arg = None
            out_arg = None
            if len(sys.argv) > idx + 1 and not sys.argv[idx + 1].startswith('-'):
                input_arg = sys.argv[idx + 1]
            if len(sys.argv) > idx + 2 and not sys.argv[idx + 2].startswith('-'):
                out_arg = sys.argv[idx + 2]

            if not input_arg:
                default_input = os.path.join(REPO_ROOT, 'audit_inputs')
                input_arg = default_input

            if not out_arg:
                # leave as None so generate_catalog will write to input_folder/Normalized
                out_arg = None

            outp = generate_catalog(input_arg, out_arg)
            if '--export-duplicates' in sys.argv:
                # export duplicates CSVs next to the workbook
                csvs = export_duplicates_csvs(outp)
                for p in csvs:
                    print(f'Wrote {p}')
        else:
            main()
    except Exception:
        import traceback
        traceback.print_exc()

