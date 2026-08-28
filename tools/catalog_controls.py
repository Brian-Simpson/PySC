#!/usr/bin/env python3
"""
Scan .audit files and produce an Excel workbook cataloging controls.

Produces one sheet per platform code discovered in descriptions (e.g. MSSRV, MSWRK, PAFW, NXOS, IOS).
Each sheet contains rows with: source file, control type, description, info, reference, and raw fields.

Usage:
  pip install openpyxl
  python tools/catalog_controls.py --input c:\PySC\audit_inputs --output controls_catalog.xlsx

If no input is provided the script will default to c:\PySC\audit_inputs (or current folder).
"""
import argparse
import os
import re
import json
from collections import defaultdict

try:
    from openpyxl import Workbook
except Exception:
    Workbook = None


FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
PLATFORM_RE = re.compile(r"\b([A-Z]{2,6})\b")


def extract_controls_with_context(text):
    """Return list of (fields_dict, condition_label, report_dict).

    Scans <if>...</if> blocks and associates custom_items inside condition
    with the enclosing <report> found in the <then> section. Also returns
    top-level custom_items with empty condition/report.
    """
    results = []

    # Process <if> blocks first
    for if_block in re.findall(r"<if>(.*?)</if>", text, flags=re.DOTALL | re.IGNORECASE):
        # condition type
        cond_type = None
        m = re.search(r"<condition[^>]*>(.*?)</condition>", if_block, flags=re.DOTALL | re.IGNORECASE)
        cond_body = m.group(1) if m else ""
        mtype = re.search(r"<condition\s+type\s*:\s*\"([^\"]+)\"", if_block, flags=re.IGNORECASE)
        if mtype:
            cond_type = mtype.group(1)
        else:
            # fallback, try to find 'type:"XXX"' anywhere in the if block
            m2 = re.search(r"type\s*:\s*\"([^\"]+)\"", if_block, flags=re.IGNORECASE)
            cond_type = m2.group(1) if m2 else ""

        # report within then
        report_fields = {}
        mthen = re.search(r"<then>(.*?)</then>", if_block, flags=re.DOTALL | re.IGNORECASE)
        then_body = mthen.group(1) if mthen else ""
        mreport = re.search(r"<report[^>]*>(.*?)</report>", then_body, flags=re.DOTALL | re.IGNORECASE)
        if mreport:
            for line in mreport.group(1).splitlines():
                fm = FIELD_RE.match(line)
                if fm:
                    report_fields[fm.group(1).lower()] = fm.group(2).strip()

        # parse custom_items inside the condition body
        items = parse_custom_items(cond_body)
        for it in items:
            results.append((it, cond_type or "", report_fields))

    # Remove processed <if> blocks to avoid double-counting top-level items
    text_no_if = re.sub(r"<if>.*?</if>", "", text, flags=re.DOTALL | re.IGNORECASE)

    # Top-level custom_items
    top_items = parse_custom_items(text_no_if)
    for it in top_items:
        results.append((it, "", {}))

    return results


def parse_custom_items(text):
    items = []
    parts = re.split(r"<custom_item>|</custom_item>", text, flags=re.IGNORECASE)
    # parts will include chunks; every odd chunk is the body
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
    # remove surrounding quotes
    d = description.strip().strip('"').strip("'")
    # look for token patterns like ' - MSSRV - ' or standalone uppercase tokens
    m = re.search(r"-\s*([A-Z]{2,6})\s*-", d)
    if m:
        return m.group(1)
    # fallback: first uppercase token of 2-6 length
    m2 = PLATFORM_RE.search(d)
    if m2:
        return m2.group(1)
    return 'UNKNOWN'


def determine_platform_from_filename(path):
    """Determine platform/type from filename using explicit rules.

    Rules (checked in order):
      - If name contains 'SQL' -> 'SQL'
      - If name contains 'Server' but NOT 'SQL' -> 'MSSRV'
      - If name contains 'IOS' -> 'IOS'
      - If name contains 'Palo Alto' -> 'PAFW'
      - If name contains 'NX' -> 'NX-OS'
      - If name contains 'F5' -> 'F5'
      - If name contains 'Azure' -> 'MSAZ'
      - If name contains 'Amazon' -> 'Amazon'

    Matching is case-insensitive and checks the file base name.
    """
    name = os.path.basename(path).lower()
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


def scan_folder(folder):
    records_by_platform = defaultdict(list)
    files = []
    for root, _, filenames in os.walk(folder):
        for f in filenames:
            if f.lower().endswith('.audit'):
                files.append(os.path.join(root, f))

    for path in sorted(files):
        with open(path, encoding='utf-8') as fh:
            txt = fh.read()

        entries = extract_controls_with_context(txt)
        for it, cond_type, report_fields in entries:
            desc = it.get('description', '')
            plat = detect_platform(desc)
            record = {
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
            records_by_platform[plat].append(record)

    return records_by_platform


def write_workbook(records_by_platform, outpath):
    if Workbook is None:
        raise RuntimeError('openpyxl is required; pip install openpyxl')

    wb = Workbook()
    # remove default sheet
    default = wb.active
    wb.remove(default)

    def _sanitize(v):
        if v is None:
            return ''
        if not isinstance(v, str):
            v = str(v)
        # remove illegal XML characters for openpyxl
        return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', v)

    for plat, rows in sorted(records_by_platform.items()):
        safe_name = plat[:31]
        ws = wb.create_sheet(title=safe_name)
        headers = [
            'source_file', 'control_type', 'description', 'info', 'reference',
            'condition_type', 'report_type', 'report_description', 'raw_fields'
        ]
        ws.append(headers)
        for r in rows:
            ws.append([_sanitize(r.get(h, '')) for h in headers])

    wb.save(outpath)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', '-i', default=r'c:\PySC\audit_inputs', help='Input folder with .audit files')
    p.add_argument('--output', '-o', default='controls_catalog.xlsx', help='Output Excel workbook')
    args = p.parse_args()

    records = scan_folder(args.input)
    write_workbook(records, args.output)
    print(f'Wrote workbook: {args.output}')


if __name__ == '__main__':
    main()
