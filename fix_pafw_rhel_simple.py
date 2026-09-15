#!/usr/bin/env python3
"""
Fix PAFW and RHEL - Direct and simple approach
"""

import re
from pathlib import Path

def get_baseline_ids(baseline_path):
    """Extract control IDs from baseline file"""
    ids = set()
    try:
        with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        for match in re.finditer(r'description\s*:\s*"([^"]*)"', content):
            desc = match.group(1)
            id_match = re.match(r'(\d+\.\d+)', desc)
            if id_match:
                ids.add(id_match.group(1))
    except:
        pass
    return ids

def fix_consolidated(consolidated_path, baseline_ids):
    """Fix a consolidated file by uncommenting baseline controls"""
    with open(consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    output = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for custom_item start (could be commented or not)
        if '<custom_item>' in line:
            # Collect the entire item
            item_lines = [line]
            i += 1
            item_id = None

            # Process lines until we find </custom_item>
            while i < len(lines):
                line = lines[i]
                item_lines.append(line)

                # Check for description to extract ID
                if 'description' in line and ':' in line:
                    match = re.search(r'description\s*:\s*"([^"]*)"', line)
                    if match:
                        desc = match.group(1)
                        id_match = re.match(r'(\d+\.\d+)', desc)
                        if id_match:
                            item_id = id_match.group(1)

                i += 1
                if '</custom_item>' in line:
                    break

            # Decide: uncomment if ID is in baseline, keep commented otherwise
            if item_id and item_id in baseline_ids:
                # Uncomment all lines in this item
                for item_line in item_lines:
                    # Remove leading # if present
                    if item_line.strip().startswith('#'):
                        output.append(item_line.lstrip('#'))
                    else:
                        output.append(item_line)
            else:
                # Keep all lines (comment if not already)
                for item_line in item_lines:
                    if not item_line.strip().startswith('#') and '<custom_item>' in item_line:
                        output.append('#' + item_line)
                    elif not item_line.strip().startswith('#') and '</' in item_line and 'custom_item' in item_line:
                        output.append('#' + item_line)
                    elif not item_line.strip().startswith('#') and item_line.strip() and not item_line.strip().startswith('<check_type'):
                        output.append('#' + item_line)
                    else:
                        output.append(item_line)
        else:
            output.append(line)
            i += 1

    return ''.join(output)

# Process PAFW
print("Processing PAFW...")
pafw_baseline_path = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit')
pafw_consolidated_path = Path(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit')

pafw_ids = get_baseline_ids(pafw_baseline_path)
print(f"  Baseline has {len(pafw_ids)} control IDs")

if pafw_ids and pafw_consolidated_path.exists():
    # Count before
    with open(pafw_consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
        before = f.read()
    before_uncommented = len(re.findall(r'^\s*<custom_item>', before, re.MULTILINE))
    before_commented = len(re.findall(r'^\s*#<custom_item>', before, re.MULTILINE))

    # Fix
    fixed = fix_consolidated(pafw_consolidated_path, pafw_ids)

    # Count after
    after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed, re.MULTILINE))
    after_commented = len(re.findall(r'^\s*#<custom_item>', fixed, re.MULTILINE))

    # Write
    with open(pafw_consolidated_path, 'w', encoding='utf-8') as f:
        f.write(fixed)

    print(f"  Before: {before_uncommented} uncommented, {before_commented} commented")
    print(f"  After:  {after_uncommented} uncommented, {after_commented} commented")
    print(f"  ✅ PAFW fixed")
else:
    print(f"  ❌ Failed - baseline IDs: {len(pafw_ids)}, file exists: {pafw_consolidated_path.exists()}")

# Process RHEL
print("\nProcessing RHEL...")
rhel_baseline_path = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit')
rhel_consolidated_path = Path(r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit')

rhel_ids = get_baseline_ids(rhel_baseline_path)
print(f"  Baseline has {len(rhel_ids)} control IDs")

if rhel_ids:
    with open(rhel_consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
        rhel_content = f.read()

    # Check if file has content
    if len(rhel_content) < 100:
        print(f"  ⚠️  RHEL consolidated file is empty or too small ({len(rhel_content)} bytes)")
        print(f"     File only contains header, no controls to fix")
    elif '<custom_item>' not in rhel_content:
        print(f"  ⚠️  RHEL consolidated file has no <custom_item> blocks")
    else:
        # Count before
        before_uncommented = len(re.findall(r'^\s*<custom_item>', rhel_content, re.MULTILINE))
        before_commented = len(re.findall(r'^\s*#<custom_item>', rhel_content, re.MULTILINE))

        # Fix
        fixed = fix_consolidated(rhel_consolidated_path, rhel_ids)

        # Count after
        after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed, re.MULTILINE))
        after_commented = len(re.findall(r'^\s*#<custom_item>', fixed, re.MULTILINE))

        # Write
        with open(rhel_consolidated_path, 'w', encoding='utf-8') as f:
            f.write(fixed)

        print(f"  Before: {before_uncommented} uncommented, {before_commented} commented")
        print(f"  After:  {after_uncommented} uncommented, {after_commented} commented")
        print(f"  ✅ RHEL fixed")
else:
    print(f"  ❌ Failed - no baseline IDs found")

print("\n" + "="*60)
print("Done!")
print("="*60)
