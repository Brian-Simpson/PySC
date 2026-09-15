#!/usr/bin/env python3
"""
Direct fix for commented controls - simpler approach
"""

import re
from pathlib import Path

def fix_audit_file(baseline_path, consolidated_path):
    """Fix a consolidated audit file based on baseline"""

    # Read baseline and extract IDs
    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        baseline_content = f.read()

    baseline_ids = set()
    for desc in re.findall(r'description\s*:\s*"([^"]*)"', baseline_content):
        match = re.match(r'(\d+\.\d+)', desc)
        if match:
            baseline_ids.add(match.group(1))

    print(f"Baseline IDs: {len(baseline_ids)}")
    if baseline_ids:
        print(f"  Sample: {sorted(baseline_ids)[:5]}")

    # Read consolidated file
    with open(consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
        consolidated_content = f.read()

    # Process line by line
    lines = consolidated_content.split('\n')
    result = []
    current_item = []
    current_id = None

    for line in lines:
        # Check if starting a custom_item (commented or not)
        if '<custom_item>' in line:
            current_item = [line.lstrip('#')]  # Remove comment if present
            current_id = None
        elif current_item:
            # We're inside a custom_item
            if 'description' in line and ':' in line:
                # Extract the ID
                match = re.search(r'description\s*:\s*"([^"]*)"', line)
                if match:
                    desc = match.group(1)
                    id_match = re.match(r'(\d+\.\d+)', desc)
                    if id_match:
                        current_id = id_match.group(1)

                # Remove comment from description line
                current_item.append(line.lstrip('#'))
            elif '</custom_item>' in line:
                # End of item - decide whether to keep or comment
                current_item.append(line.lstrip('#'))

                if current_id and current_id in baseline_ids:
                    # Uncommented - add as-is
                    result.extend(current_item)
                else:
                    # Commented - add with # prefix
                    result.extend(['#' + line for line in current_item])

                current_item = []
                current_id = None
            else:
                # Regular line inside item
                current_item.append(line.lstrip('#'))
        else:
            # Outside custom_item
            result.append(line)

    # Handle any remaining item
    if current_item:
        if current_id and current_id in baseline_ids:
            result.extend(current_item)
        else:
            result.extend(['#' + line for line in current_item])

    return '\n'.join(result), baseline_ids

# Fix PAFW
print("=" * 60)
print("Fixing PAFW...")
print("=" * 60)
pafw_baseline = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit')
pafw_consolidated = Path(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit')

if pafw_baseline.exists() and pafw_consolidated.exists():
    fixed_content, baseline_ids = fix_audit_file(pafw_baseline, pafw_consolidated)

    before_uncommented = len(re.findall(r'^\s*<custom_item>', open(pafw_consolidated).read(), re.MULTILINE))
    after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))

    print(f"Before: {before_uncommented} uncommented")
    print(f"After:  {after_uncommented} uncommented")

    with open(pafw_consolidated, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    print("✅ Written to disk\n")
else:
    print("ERROR: Files not found\n")

# Fix RHEL
print("=" * 60)
print("Fixing RHEL...")
print("=" * 60)
rhel_baseline = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit')
rhel_consolidated = Path(r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit')

if rhel_baseline.exists() and rhel_consolidated.exists():
    with open(rhel_consolidated, 'r', encoding='utf-8', errors='ignore') as f:
        rhel_content = f.read()

    if '<custom_item>' not in rhel_content:
        print("WARNING: RHEL consolidated file is empty or has no controls")
        print("Not processing RHEL\n")
    else:
        fixed_content, baseline_ids = fix_audit_file(rhel_baseline, rhel_consolidated)

        before_uncommented = len(re.findall(r'^\s*<custom_item>', rhel_content, re.MULTILINE))
        after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))

        print(f"Before: {before_uncommented} uncommented")
        print(f"After:  {after_uncommented} uncommented")

        with open(rhel_consolidated, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        print("✅ Written to disk\n")
else:
    print("ERROR: Files not found\n")

print("=" * 60)
print("Done!")
print("=" * 60)
