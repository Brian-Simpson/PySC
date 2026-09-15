#!/usr/bin/env python3
"""
Fix PAFW and RHEL by regenerating consolidated files from input files
using baseline controls to determine which to uncomment
"""

import re
from pathlib import Path

def get_baseline_ids(baseline_path):
    """Extract control IDs from baseline"""
    ids = set()
    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        for match in re.finditer(r'description\s*:\s*"(\d+\.\d+)', f.read()):
            ids.add(match.group(1))
    return ids

def regenerate_consolidated(input_path, baseline_ids):
    """Regenerate consolidated file from input, with only baseline controls uncommented"""
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Split into header and controls
    header_match = re.search(r'^(.*?)<custom_item>', content, re.DOTALL)
    if not header_match:
        return content

    header = header_match.group(1)
    footer = '</check_type>'

    # Extract all custom_item blocks
    items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)

    output_lines = [header]

    for item in items:
        # Extract control ID from description
        desc_match = re.search(r'description\s*:\s*"(\d+\.\d+)', item)
        if desc_match:
            control_id = desc_match.group(1)
            if control_id in baseline_ids:
                # Uncomment
                output_lines.append(item + '\n')
            else:
                # Comment
                commented = '\n'.join('#' + line for line in item.split('\n')) + '\n'
                output_lines.append(commented)
        else:
            # No ID found, keep as is
            output_lines.append(item + '\n')

    output_lines.append(footer)
    return ''.join(output_lines)

# Process PAFW
print("Regenerating PAFW...")
pafw_input = Path(r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit')
pafw_baseline = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit')
pafw_output = Path(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit')

pafw_baseline_ids = get_baseline_ids(pafw_baseline)
print(f"  Baseline has {len(pafw_baseline_ids)} control IDs")

if pafw_input.exists() and pafw_output.exists():
    with open(pafw_output, 'r', encoding='utf-8', errors='ignore') as f:
        before = f.read()
    before_uncommented = len(re.findall(r'^\s*<custom_item>', before, re.MULTILINE))

    fixed_content = regenerate_consolidated(pafw_input, pafw_baseline_ids)

    after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))

    with open(pafw_output, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print(f"  Before: {before_uncommented} uncommented")
    print(f"  After:  {after_uncommented} uncommented")
    print(f"  ✅ PAFW regenerated")
else:
    print(f"  ❌ Files not found")

# Process RHEL
print("\nRegenerating RHEL...")
rhel_input = Path(r'C:\PySC\TAP\Output\Processed\For_Gap\RHEL.audit')
rhel_baseline = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit')
rhel_output = Path(r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit')

rhel_baseline_ids = get_baseline_ids(rhel_baseline)
print(f"  Baseline has {len(rhel_baseline_ids)} control IDs")

if rhel_input.exists() and rhel_output.exists():
    with open(rhel_output, 'r', encoding='utf-8', errors='ignore') as f:
        before = f.read()
    before_uncommented = len(re.findall(r'^\s*<custom_item>', before, re.MULTILINE))

    fixed_content = regenerate_consolidated(rhel_input, rhel_baseline_ids)

    after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))

    with open(rhel_output, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print(f"  Before: {before_uncommented} uncommented")
    print(f"  After:  {after_uncommented} uncommented")
    print(f"  ✅ RHEL regenerated")
else:
    print(f"  ❌ Files not found")

print("\n" + "="*60)
print("Done!")
print("="*60)
