import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

SECCON_DIR = Path("c:/PySC/SecCon-Framework")
POLICY_MAP_DIR = Path("c:/PySC/policy_maps")
AUDIT_DIR = Path("c:/PySC/Audits")

VENDOR_KEYWORDS = {
    "f5": ["f5", "big-ip"],
    "paloalto": ["palo alto", "paloalto", "pan-os"],
    "cisco_ios": ["cisco_ios", "cisco ios", "ios"],
    "cisco_nxos": ["cisco_nx-os", "cisco nxos", "nxos"],
    "cisco_asa": ["cisco_asa", "asa"],
}

POLICY_META_KEYWORDS = [
    "policy", "account", "password", "lockout", "audit", "firewall", "network", "user rights", "uac", "bitlocker",
]


def parse_markdown_tables(content: str) -> List[Dict[str, str]]:
    rows = []
    lines = content.splitlines()
    table_header = None
    table_cols = []
    collecting = False

    for line in lines:
        if line.strip().startswith("|") and "|" in line:
            cells = [cell.strip() for cell in line.strip().split("|")][1:-1]
            if all(re.match(r'^[\-\s:]+$', c) for c in cells):
                collecting = True
                continue
            if not collecting:
                table_header = cells
                continue
            if table_header and collecting:
                if len(cells) == len(table_header):
                    row = {table_header[i]: cells[i] for i in range(len(table_header))}
                    rows.append(row)
                else:
                    # row length mismatch; skip malformed rows
                    continue
        else:
            table_header = None
            collecting = False
    return rows


def load_seccon_policy_catalog(seccon_dir: Path) -> pd.DataFrame:
    records = []
    if not seccon_dir.exists():
        raise FileNotFoundError(f"SecCon directory not found: {seccon_dir}")

    for md_file in sorted(seccon_dir.glob("level-*.md")):
        content = md_file.read_text(encoding="utf-8", errors="ignore")
        markdown_tables = parse_markdown_tables(content)
        for row in markdown_tables:
            row_clean = {k.strip(): v.strip() for k, v in row.items()}
            row_clean["source_file"] = md_file.name
            records.append(row_clean)

    if not records:
        raise ValueError("No SecCon policy rows parsed from markdown files.")
    return pd.DataFrame(records)


def parse_audit_blocks(audit_text: str) -> List[Dict[str, str]]:
    blocks = []
    lines = audit_text.splitlines()
    in_block = False
    block_lines = []
    start_pattern = re.compile(r"^\s*<(custom_item|item)>\s*$", re.IGNORECASE)
    end_pattern = re.compile(r"^\s*</(custom_item|item)>\s*$", re.IGNORECASE)

    for line in lines:
        if not in_block and start_pattern.match(line):
            in_block = True
            block_lines = [line]
            continue
        if in_block:
            block_lines.append(line)
            if end_pattern.match(line):
                blocks.append("\n".join(block_lines))
                in_block = False
    return [parse_block_to_dict(block) for block in blocks]


def parse_block_to_dict(block: str) -> Dict[str, str]:
    result = {}
    current_key = None
    current_value_lines: List[str] = []
    in_multiline = False
    key_pattern = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")

    def flush():
        nonlocal current_key, current_value_lines, in_multiline
        if current_key is None:
            return
        value = "\n".join(current_value_lines).rstrip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        result[current_key] = value
        current_key = None
        current_value_lines = []
        in_multiline = False

    for line in block.splitlines():
        match = key_pattern.match(line)
        if match and not in_multiline:
            if current_key is not None:
                flush()
            current_key = match.group(1).strip()
            raw_value = match.group(2).rstrip()
            if raw_value.startswith('"') and not raw_value.endswith('"'):
                in_multiline = True
                current_value_lines = [raw_value[1:]]
            else:
                if raw_value.startswith('"') and raw_value.endswith('"'):
                    raw_value = raw_value[1:-1]
                result[current_key] = raw_value
                current_key = None
        elif in_multiline:
            current_value_lines.append(line)
            if line.rstrip().endswith('"'):
                flush()
    flush()
    return result


def classify_vendor_file(file_name: str) -> Optional[str]:
    name = file_name.lower()
    if "f5" in name or "big-ip" in name:
        return "f5"
    if "palo" in name or "pan-os" in name:
        return "paloalto"
    if "cisco_ios" in name or "cisco ios" in name or "ios" in name:
        if "nx" not in name and "asa" not in name:
            return "cisco_ios"
    if "nx-os" in name or "nxos" in name:
        return "cisco_nxos"
    if "asa" in name:
        return "cisco_asa"
    return None


def detect_vendor_from_block(block: Dict[str, str]) -> Optional[str]:
    text = " ".join(str(block.get(k, "")) for k in ["description", "info", "reference"])
    text = text.lower()
    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(k in text for k in keywords):
            return vendor
    return None


def build_vendor_summary(audit_dir: Path) -> pd.DataFrame:
    records = []
    files = sorted(audit_dir.glob("*.audit"))
    for audit_file in files:
        text = audit_file.read_text(encoding="utf-8", errors="ignore")
        vendor = classify_vendor_file(audit_file.name)
        blocks = parse_audit_blocks(text)
        block_vendors = {detect_vendor_from_block(b) for b in blocks if detect_vendor_from_block(b)}
        block_vendors = sorted(v for v in block_vendors if v)
        records.append({
            "audit_file": audit_file.name,
            "vendor_from_name": vendor or "windows/other",
            "vendor_from_blocks": ", ".join(block_vendors) if block_vendors else "",
            "block_count": len(blocks),
        })
    return pd.DataFrame(records)


def build_vendor_map_skeletons(vendor_summary: pd.DataFrame, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    vendor_files: Dict[str, List[str]] = {}
    for _, row in vendor_summary.iterrows():
        vendor = row["vendor_from_name"]
        if vendor not in vendor_files:
            vendor_files[vendor] = []
        vendor_files[vendor].append(row["audit_file"])

    for vendor_key in ["f5", "paloalto", "cisco_ios", "cisco_nxos", "cisco_asa"]:
        existing = vendor_files.get(vendor_key, [])
        skeleton = {
            "vendor": vendor_key,
            "audit_files": existing,
            "description": "Placeholder policy map for vendor-specific security controls.",
            "mappings": {},
        }
        out_path = output_dir / f"{vendor_key}_policy_map.json"
        if not out_path.exists():
            out_path.write_text(json.dumps(skeleton, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Build SecCon policy catalog and vendor-specific audit mapping summary.")
    parser.add_argument("--audit-dir", default=str(AUDIT_DIR), help="Path to the audit files directory.")
    parser.add_argument("--seccon-dir", default=str(SECCON_DIR), help="Path to the local SecCon Framework directory.")
    parser.add_argument("--report", default="c:/PySC/secccon_policy_map_report.xlsx", help="Excel report path.")
    parser.add_argument("--generate-skeletons", action="store_true", help="Generate vendor policy map skeleton JSON files.")
    args = parser.parse_args()

    seccon_path = Path(args.seccon_dir)
    audit_path = Path(args.audit_dir)
    report_path = Path(args.report)

    seccon_catalog = load_seccon_policy_catalog(seccon_path)
    vendor_summary = build_vendor_summary(audit_path)

    print(f"Loaded {len(seccon_catalog)} SecCon policy rows from {seccon_path}.")
    print("Vendor audit discovery:")
    print(vendor_summary.groupby('vendor_from_name').size())

    if args.generate_skeletons:
        build_vendor_map_skeletons(vendor_summary, POLICY_MAP_DIR)
        print(f"Generated skeleton mapping JSON files in {POLICY_MAP_DIR}")

    with pd.ExcelWriter(report_path, engine="openpyxl") as writer:
        seccon_catalog.to_excel(writer, sheet_name="SecConPolicies", index=False)
        vendor_summary.to_excel(writer, sheet_name="VendorAuditSummary", index=False)

    print(f"Created report: {report_path}")


if __name__ == "__main__":
    main()
