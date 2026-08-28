#!/usr/bin/env python3
"""
Extract vendor controls and match to SecCon policies with progress reporting.
Optimized for performance with keyword-based pre-filtering.
"""
import json
import sys
import re
from pathlib import Path
from difflib import SequenceMatcher
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import time


def normalize_text(text: str) -> str:
    """Normalize text for comparison."""
    return re.sub(r'[^a-z0-9\s]', ' ', text.lower())


def extract_keywords(text: str) -> Set[str]:
    """Extract keywords (>4 chars) from normalized text."""
    return {word for word in normalize_text(text).split() if len(word) > 4}


def similarity_score(text1: str, text2: str) -> float:
    """Compute sequence similarity score."""
    norm1 = normalize_text(text1)
    norm2 = normalize_text(text2)
    return SequenceMatcher(None, norm1, norm2).ratio()


def keyword_overlap_score(text1: str, text2: str) -> float:
    """Compute keyword overlap score (Jaccard similarity)."""
    kw1 = extract_keywords(text1)
    kw2 = extract_keywords(text2)
    if not kw1 or not kw2:
        return 0.0
    union = kw1 | kw2
    if not union:
        return 0.0
    return len(kw1 & kw2) / len(union)


def parse_audit_blocks(audit_text: str) -> List[Dict[str, str]]:
    """Parse <custom_item> and <item> blocks from audit text."""
    blocks = []
    pattern = r'<custom_item>.*?</custom_item>|<item>.*?</item>'

    for match in re.finditer(pattern, audit_text, re.DOTALL):
        block_text = match.group(0)
        block = parse_block_to_dict(block_text)
        if block:
            blocks.append(block)

    return blocks


def parse_block_to_dict(block_text: str) -> Optional[Dict[str, str]]:
    """Parse a block into key-value dictionary."""
    block_dict = {}
    in_multiline_value = False
    current_key = None
    lines = block_text.split('\n')

    for line in lines:
        # Skip opening/closing tags
        if line.strip().startswith('<') and line.strip().endswith('>'):
            continue

        # Check for key: value pattern
        if ':' in line and not in_multiline_value:
            parts = line.split(':', 1)
            if len(parts) == 2:
                current_key = parts[0].strip().lower()
                value = parts[1].strip()

                # Check if value is quoted
                if value.startswith('"'):
                    if value.endswith('"'):
                        block_dict[current_key] = value[1:-1]
                        current_key = None
                    else:
                        in_multiline_value = True
                        block_dict[current_key] = value[1:]
                else:
                    block_dict[current_key] = value
                    current_key = None
        elif in_multiline_value and current_key:
            if line.strip().endswith('"'):
                block_dict[current_key] += '\n' + line.rstrip('"').strip()
                in_multiline_value = False
                current_key = None
            else:
                block_dict[current_key] += '\n' + line.strip()

    return block_dict if block_dict else None


def load_seccon_policies(seccon_dir: str) -> List[Dict[str, str]]:
    """Load SecCon policies from markdown files."""
    policies = []
    seccon_path = Path(seccon_dir)

    for level_file in sorted(seccon_path.glob('level-*.md')):
        try:
            content = level_file.read_text(encoding='utf-8', errors='ignore')
            policies.extend(parse_markdown_tables(content))
        except Exception as e:
            print(f"  Warning: Error reading {level_file}: {e}")

    return policies


def parse_markdown_tables(content: str) -> List[Dict[str, str]]:
    """Extract policy rows from markdown tables."""
    rows = []
    in_table = False
    headers = []

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if '|' not in line:
            in_table = False
            continue

        if not in_table:
            # First line is headers
            headers = [h.strip() for h in line.split('|')[1:-1]]
            in_table = True
            continue

        # Skip separator line
        if all(c in '-|: ' for c in line):
            continue

        # Parse data row
        try:
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if len(cells) == len(headers):
                row = dict(zip(headers, cells))
                rows.append(row)
        except Exception:
            continue

    return rows


def match_control_to_secccon_fast(
    vendor_control: Dict[str, str],
    secccon_policies: List[Dict[str, str]],
    threshold: float = 0.3,
) -> Optional[Tuple[Dict[str, str], float]]:
    """
    Match vendor control to best SecCon policy with keyword pre-filtering.
    """
    description = vendor_control.get("description", "")
    info = vendor_control.get("info", "")
    solution = vendor_control.get("solution", "")
    vendor_text = f"{description} {info} {solution}"

    if not vendor_text.strip():
        return None

    vendor_keywords = extract_keywords(vendor_text)
    best_match = None
    best_score = 0.0
    candidates_checked = 0

    # Pre-filter by keyword overlap
    for policy in secccon_policies:
        policy_text = " ".join(str(policy.get(k, "")) for k in ["Feature", "Policy Setting", "Description"])
        policy_keywords = extract_keywords(policy_text)

        # Quick rejection if no keyword overlap
        if not (vendor_keywords & policy_keywords):
            continue

        candidates_checked += 1

        # Compute weighted score only for candidates
        sim = similarity_score(vendor_text, policy_text)
        kw_overlap = keyword_overlap_score(vendor_text, policy_text)
        combined_score = 0.7 * sim + 0.3 * kw_overlap

        if combined_score > best_score:
            best_score = combined_score
            best_match = policy

            # Early exit if very good match
            if best_score > 0.7:
                break

    if best_score >= threshold:
        return (best_match, best_score)
    return None


def process_vendor(
    vendor_name: str,
    audit_files: List[Path],
    secccon_policies: List[Dict[str, str]],
    output_dir: Path,
    threshold: float = 0.35,
) -> Dict:
    """Process all audit files for a vendor."""
    all_controls = []
    matched_controls = []

    start_time = time.time()

    for file_idx, audit_file in enumerate(audit_files, 1):
        try:
            audit_text = audit_file.read_text()
            blocks = parse_audit_blocks(audit_text)

            print(f"    [{file_idx}/{len(audit_files)}] {audit_file.name}: {len(blocks)} controls")

            for block_idx, block in enumerate(blocks):
                control_id = f"{audit_file.stem}_{block_idx}"
                block['_file'] = audit_file.name
                block['_index'] = block_idx
                all_controls.append(block)

                # Match control
                match_result = match_control_to_secccon_fast(block, secccon_policies, threshold)
                if match_result:
                    policy, score = match_result
                    matched_controls.append({
                        'vendor_control': block,
                        'secccon_policy': policy,
                        'score': score
                    })

        except Exception as e:
            print(f"    Error processing {audit_file}: {e}")

    elapsed = time.time() - start_time

    # Summary
    total = len(all_controls)
    matched = len(matched_controls)
    match_pct = (matched / total * 100) if total > 0 else 0

    print(f"  Total Controls: {total}")
    print(f"  Matched: {matched} ({match_pct:.1f}%)")
    print(f"  Time: {elapsed:.1f}s")

    # Save JSON
    output_data = {
        'vendor': vendor_name,
        'total_controls': total,
        'matched_controls': matched,
        'match_percentage': match_pct,
        'mappings': {}
    }

    for i, match in enumerate(matched_controls):
        control = match['vendor_control']
        policy = match['secccon_policy']
        score = match['score']

        output_data['mappings'][f"{i}"] = {
            'vendor_control_id': control.get('_file', '') + f"_{control.get('_index', i)}",
            'vendor_control_desc': control.get('description', ''),
            'matched_secccon_policy': policy.get('Policy Setting', ''),
            'match_score': score
        }

    output_file = output_dir / f"{vendor_name}_policy_map.json"
    output_file.write_text(json.dumps(output_data, indent=2))

    return output_data


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--threshold', type=float, default=0.35)
    parser.add_argument('--vendors', default='all', help='Comma-separated vendor names or "all"')
    args = parser.parse_args()

    AUDIT_DIR = Path("c:/PySC/Audits")
    SECCON_DIR = Path("c:/PySC/SecCon-Framework")
    OUTPUT_DIR = Path("c:/PySC/policy_maps")
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Load SecCon policies
    print("Loading SecCon policies...")
    secccon_policies = load_seccon_policies(str(SECCON_DIR))
    print(f"  Loaded {len(secccon_policies)} SecCon policies.\n")

    # Organize audit files by vendor
    vendors = defaultdict(list)

    VENDOR_MAP = {
        "f5": "f5",
        "big-ip": "f5",
        "palo alto": "paloalto",
        "paloalto": "paloalto",
        "pan-os": "paloalto",
        "cisco": "cisco",
        "ios": "cisco_ios",
        "nxos": "cisco_nxos",
        "asa": "cisco_asa",
    }

    for audit_file in sorted(AUDIT_DIR.glob("*.audit")):
        filename_lower = audit_file.name.lower()
        vendor = "windows"

        for keyword, vendor_name in VENDOR_MAP.items():
            if keyword in filename_lower:
                vendor = vendor_name
                break

        vendors[vendor].append(audit_file)

    # Process requested vendors
    requested_vendors = args.vendors.split(',') if args.vendors != 'all' else list(vendors.keys())

    for vendor in sorted(requested_vendors):
        if vendor not in vendors:
            print(f"Vendor '{vendor}' not found.")
            continue

        audit_files = vendors[vendor]
        print(f"Processing {vendor.upper()} ({len(audit_files)} files)...")

        result = process_vendor(
            vendor,
            audit_files,
            secccon_policies,
            OUTPUT_DIR,
            threshold=args.threshold
        )

        print()

    print("Done!")


if __name__ == "__main__":
    main()
