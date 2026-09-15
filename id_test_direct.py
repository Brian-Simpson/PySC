#!/usr/bin/env python3
"""Direct test of the matching logic"""

import re

# Test the ID matching logic directly
def extract_id(description):
    id_match = re.match(r'(\d+\.\d+)', description)
    if not id_match:
        return None
    return id_match.group(1)

baseline_descriptions = [
    "1.0000 - PAFW - NetPAFW - Audit Logging - configuration",
    "1.0001 - PAFW - NetPAFW - Audit Logging - user-id",
    "1.0002 - PAFW - NetPAFW - Audit Logging - hip match",
]

consolidated_descriptions = [
    "1.0000 - PAFW - Ensure Password Profiles do not exist",
    "1.0001 - PAFW - Ensure Password Profiles do not exist",
    "1.0002 - PAFW - Ensure valid certificate is set",
    "2.0000 - PAFW - Some other control",
]

# Extract IDs
baseline_ids = set()
for desc in baseline_descriptions:
    id_val = extract_id(desc)
    if id_val:
        baseline_ids.add(id_val)

print(f"Baseline IDs: {sorted(baseline_ids)}")
print("\nConsolidated controls:")
for desc in consolidated_descriptions:
    id_val = extract_id(desc)
    is_used = id_val in baseline_ids if id_val else False
    status = "UNCOMMENT" if is_used else "COMMENT"
    print(f"  {status:9} - {desc}")

# Write to file
with open(r'C:\PySC\TAP\id_test_results.txt', 'w') as f:
    f.write(f"Baseline IDs: {sorted(baseline_ids)}\n\n")
    for desc in consolidated_descriptions:
        id_val = extract_id(desc)
        is_used = id_val in baseline_ids if id_val else False
        status = "UNCOMMENT" if is_used else "COMMENT"
        f.write(f"{status:9} - {desc}\n")

print("\nResults written to id_test_results.txt")
