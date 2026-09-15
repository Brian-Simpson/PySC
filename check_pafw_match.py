#!/usr/bin/env python3
"""Check why PAFW and RHEL aren't matching"""

import re
from pathlib import Path

def extract_ids_from_file(filepath):
    """Extract all control IDs from a file"""
    ids = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        descriptions = re.findall(r'description\s*:\s*"([^"]*)"', content)
        for desc in descriptions:
            id_match = re.match(r'(\d+\.\d+)', desc)
            if id_match:
                ids.add(id_match.group(1))
    except:
        pass
    return ids

# Check PAFW
pafw_baseline = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'
pafw_consolidated = r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit'

baseline_ids = extract_ids_from_file(pafw_baseline)
consolidated_ids = extract_ids_from_file(pafw_consolidated)

with open(r'C:\PySC\TAP\check_pafw_match.txt', 'w') as f:
    f.write(f"PAFW Baseline IDs: {sorted(baseline_ids)[:10]} (total: {len(baseline_ids)})\n")
    f.write(f"PAFW Consolidated IDs: {sorted(consolidated_ids)[:10]} (total: {len(consolidated_ids)})\n")
    f.write(f"Match count: {len(baseline_ids & consolidated_ids)}\n")

    # Show some baseline IDs
    f.write(f"\nSample baseline IDs:\n")
    for id_ in list(sorted(baseline_ids))[:5]:
        f.write(f"  {id_}\n")

    # Show some consolidated IDs
    f.write(f"\nSample consolidated IDs:\n")
    for id_ in list(sorted(consolidated_ids))[:5]:
        f.write(f"  {id_}\n")

print("Results written to check_pafw_match.txt")
