"""
Vendor-specific policy control extraction and SecCon mapping engine.
Parses F5, Palo Alto, and Cisco audit files to extract controls,
then matches them semantically to SecCon Windows policy catalog.
"""

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from difflib import SequenceMatcher

import pandas as pd


AUDIT_DIR = Path("c:/PySC/Audits")
POLICY_MAP_DIR = Path("c:/PySC/policy_maps")
SECCON_DIR = Path("c:/PySC/SecCon-Framework")


def parse_block_to_dict(block: str) -> Dict[str, str]:
    """Parse a <custom_item> or <item> block into a dict."""
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


def parse_audit_blocks(audit_text: str) -> List[Dict[str, str]]:
    """Extract all custom_item/item blocks from audit file."""
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


def normalize_text(text: str) -> str:
    """Normalize text for comparison: lowercase, remove special chars, collapse spaces."""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_keywords(text: str) -> Set[str]:
    """Extract meaningful keywords from text (words > 4 chars)."""
    normalized = normalize_text(text)
    return set(w for w in normalized.split() if len(w) > 4)


def similarity_score(text1: str, text2: str) -> float:
    """Compute a similarity score between two texts (0.0 to 1.0)."""
    norm1 = normalize_text(text1)
    norm2 = normalize_text(text2)
    matcher = SequenceMatcher(None, norm1, norm2)
    return matcher.ratio()


def keyword_overlap_score(text1: str, text2: str) -> float:
    """Compute keyword overlap as a fraction of union size."""
    kw1 = extract_keywords(text1)
    kw2 = extract_keywords(text2)
    if not kw1 and not kw2:
        return 1.0
    if not kw1 or not kw2:
        return 0.0
    overlap = len(kw1 & kw2)
    union = len(kw1 | kw2)
    return overlap / union if union > 0 else 0.0


def match_control_to_secccon(
    vendor_control: Dict[str, str],
    secccon_policies: List[Dict[str, str]],
    threshold: float = 0.3,
) -> Optional[Tuple[Dict[str, str], float]]:
    """
    Match a vendor control to the best-matching SecCon policy.
    Uses heuristic filtering and early exit for performance.
    Returns (matched_policy, score) or None if no match above threshold.
    """
    description = vendor_control.get("description", "")
    info = vendor_control.get("info", "")
    solution = vendor_control.get("solution", "")
    vendor_text = f"{description} {info} {solution}"
    vendor_keywords = extract_keywords(vendor_text)

    best_match = None
    best_score = 0.0

    # Pre-filter by keyword overlap to reduce comparisons
    candidates = []
    for policy in secccon_policies:
        policy_text = " ".join(str(policy.get(k, "")) for k in ["Feature", "Policy Setting", "Description"])
        policy_keywords = extract_keywords(policy_text)
        
        # Quick rejection if no keyword overlap
        if not (vendor_keywords & policy_keywords):
            continue
        
        candidates.append((policy, policy_keywords))

    # Only do expensive similarity comparisons on pre-filtered candidates
    for policy, _ in candidates:
        policy_text = " ".join(str(policy.get(k, "")) for k in ["Feature", "Policy Setting", "Description"])
        
        # Compute weighted score
        sim = similarity_score(vendor_text, policy_text)
        kw_overlap = keyword_overlap_score(vendor_text, policy_text)
        
        # Weight: 70% sequence similarity, 30% keyword overlap
        combined_score = 0.7 * sim + 0.3 * kw_overlap
        
        if combined_score > best_score:
            best_score = combined_score
            best_match = policy
            
            # Early exit if we find a very good match
            if best_score > 0.7:
                break

    if best_score >= threshold:
        return (best_match, best_score)
    return None


def extract_vendor_controls(audit_file: Path) -> List[Dict[str, str]]:
    """Extract all controls from a vendor audit file."""
    text = audit_file.read_text(encoding="utf-8", errors="ignore")
    blocks = parse_audit_blocks(text)
    return [
        {
            "audit_file": audit_file.name,
            "description": block.get("description", ""),
            "info": block.get("info", ""),
            "reference": block.get("reference", ""),
            "solution": block.get("solution", ""),
            "severity": block.get("severity", ""),
            "type": block.get("type", ""),
            "block_type": block.get("block_type", "custom_item"),
        }
        for block in blocks
    ]


def load_secccon_policies(seccon_dir: Path) -> List[Dict[str, str]]:
    """Load SecCon policies from markdown files."""
    policies = []
    for md_file in sorted(seccon_dir.glob("level-*.md")):
        content = md_file.read_text(encoding="utf-8", errors="ignore")
        
        # Simple markdown table parser
        lines = content.splitlines()
        table_header = None
        collecting = False
        
        for line in lines:
            if line.strip().startswith("|") and "|" in line:
                cells = [cell.strip() for cell in line.strip().split("|")][1:-1]
                
                # Skip separator row
                if all(re.match(r'^[\-\s:]+$', c) for c in cells):
                    collecting = True
                    continue
                
                # Parse header
                if not collecting and not table_header:
                    table_header = cells
                    continue
                
                # Parse data rows
                if table_header and collecting:
                    if len(cells) == len(table_header):
                        row = {table_header[i]: cells[i] for i in range(len(table_header))}
                        row["source_file"] = md_file.name
                        policies.append(row)
            else:
                table_header = None
                collecting = False
    
    return policies


def build_vendor_mappings(
    vendor_key: str,
    audit_files: List[str],
    secccon_policies: List[Dict[str, str]],
    audit_dir: Path,
    threshold: float = 0.35,
) -> Dict[str, any]:
    """Build mappings from vendor audit files to SecCon policies."""
    vendor_controls = []
    
    for audit_file_name in audit_files:
        audit_path = audit_dir / audit_file_name
        if not audit_path.exists():
            continue
        
        controls = extract_vendor_controls(audit_path)
        vendor_controls.extend(controls)
    
    mappings = {}
    for i, control in enumerate(vendor_controls):
        match_result = match_control_to_secccon(control, secccon_policies, threshold=threshold)
        
        if match_result:
            matched_policy, score = match_result
            control_id = f"control_{i:04d}"
            mappings[control_id] = {
                "vendor_control": {
                    "description": control["description"][:200],
                    "reference": control["reference"],
                    "severity": control["severity"],
                },
                "matched_secccon_policy": {
                    "feature": matched_policy.get("Feature", ""),
                    "setting": matched_policy.get("Policy Setting", ""),
                    "description": matched_policy.get("Description", "")[:200],
                    "source": matched_policy.get("source_file", ""),
                },
                "match_score": round(score, 3),
            }
    
    return {
        "vendor": vendor_key,
        "total_controls": len(vendor_controls),
        "matched_controls": len(mappings),
        "match_percentage": round(100 * len(mappings) / len(vendor_controls), 1) if vendor_controls else 0,
        "mappings": mappings,
    }


def main():
    parser = argparse.ArgumentParser(description="Extract vendor controls and map to SecCon policies.")
    parser.add_argument("--audit-dir", default=str(AUDIT_DIR), help="Path to audit files.")
    parser.add_argument("--seccon-dir", default=str(SECCON_DIR), help="Path to SecCon Framework.")
    parser.add_argument("--map-dir", default=str(POLICY_MAP_DIR), help="Path to output policy map dir.")
    parser.add_argument("--threshold", type=float, default=0.35, help="Match score threshold (0.0-1.0).")
    parser.add_argument("--report", default="c:/PySC/vendor_control_mapping_report.xlsx", help="Excel report path.")
    args = parser.parse_args()

    audit_path = Path(args.audit_dir)
    seccon_path = Path(args.seccon_dir)
    map_path = Path(args.map_dir)
    report_path = Path(args.report)

    # Load SecCon policies once
    print("Loading SecCon policies...")
    secccon_policies = load_secccon_policies(seccon_path)
    print(f"  Loaded {len(secccon_policies)} SecCon policies.")

    # Build vendor mapping skeletons (from previous run)
    vendor_skeletons = {
        "f5": ["CIS_F5_Networks_Benchmark_v1.0.0_L1.audit", "CIS_F5_Networks_Benchmark_v1.0.0_L2 (1).audit", "CIS_F5_Networks_Benchmark_v1.0.0_L2.audit"],
        "paloalto": [
            "CIS_Palo_Alto_Firewall_10_Benchmark_v1.3.0_L2.audit",
            "CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1 (1).audit",
            "CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1 (2).audit",
            "CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1 (3).audit",
            "CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit",
        ],
        "cisco_ios": ["CIS_Cisco_IOS_12_v4.0.0_Level_1.audit", "CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit"],
        "cisco_nxos": ["CIS_Cisco_NX-OS_v1.2.0_L1.audit"],
        "cisco_asa": [],
    }

    report_records = []

    # Process each vendor
    for vendor_key, audit_files in vendor_skeletons.items():
        if not audit_files:
            print(f"\n{vendor_key}: No audit files found. Skipping.")
            continue

        print(f"\nProcessing {vendor_key}...")
        mapping_result = build_vendor_mappings(
            vendor_key,
            audit_files,
            secccon_policies,
            audit_path,
            threshold=args.threshold,
        )

        # Save to JSON
        output_json = map_path / f"{vendor_key}_policy_map.json"
        output_json.write_text(json.dumps(mapping_result, indent=2))
        print(f"  Extracted {mapping_result['total_controls']} controls.")
        print(f"  Matched {mapping_result['matched_controls']} ({mapping_result['match_percentage']}%).")
        print(f"  Saved to {output_json.name}.")

        # Collect for report
        report_records.append({
            "vendor": vendor_key,
            "total_controls": mapping_result["total_controls"],
            "matched_controls": mapping_result["matched_controls"],
            "match_percentage": mapping_result["match_percentage"],
            "files": len(audit_files),
        })

    # Write summary report
    if report_records:
        report_df = pd.DataFrame(report_records)
        report_df.to_excel(report_path, index=False, sheet_name="VendorMappingSummary")
        print(f"\nSummary report saved to {report_path}.")


if __name__ == "__main__":
    main()
