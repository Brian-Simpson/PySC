#!/usr/bin/env python3
"""Test the baseline loading and ID matching"""

import sys
import re
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator, AuditItem
from pathlib import Path

# Load a baseline
baseline_path = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'

print(f"Reading baseline: {baseline_path}")
with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)
print(f"Found {len(items)} items in baseline")

baseline_ids = set()
for item in items[:5]:  # First 5
    item_obj = AuditItem(item)
    if item_obj.description:
        # Extract ID
        id_match = re.match(r'(\d+\.\d+)', item_obj.description)
        if id_match:
            baseline_ids.add(id_match.group(1))
            print(f"  ID: {id_match.group(1):6} - {item_obj.description[:60]}")

# Now test matching
consolidated_descriptions = [
    "1.0000 - PAFW - Ensure Password Profiles do not exist",
    "1.0001 - PAFW - Ensure Password Profiles do not exist",
    "2.0001 - PAFW - Some other control",
]

print(f"\nBaseline IDs: {baseline_ids}")
print("\nTesting consolidated descriptions:")
for desc in consolidated_descriptions:
    id_match = re.match(r'(\d+\.\d+)', desc)
    if id_match:
        control_id = id_match.group(1)
        is_used = control_id in baseline_ids
        print(f"  {control_id}: {is_used:5} - {desc}")
