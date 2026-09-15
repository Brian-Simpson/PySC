#!/usr/bin/env python3
"""
Fix commented controls in consolidated audit files.
Uncomments all controls found in the corresponding baseline file.
"""

import re
import sys
from pathlib import Path

def extract_control_ids(content):
    """Extract all control IDs from audit file content"""
    ids = set()
    # Find all description fields
    descriptions = re.findall(r'description\s*:\s*"([^"]*)"', content)
    for desc in descriptions:
        # Extract ID (e.g., "1.0000" from "1.0000 - PAFW - ...")
        id_match = re.match(r'(\d+\.\d+)', desc)
        if id_match:
            ids.add(id_match.group(1))
    return ids

def uncomment_controls_by_id(consolidated_content, baseline_ids):
    """Uncomment controls whose IDs are in baseline_ids"""
    lines = consolidated_content.split('\n')
    result_lines = []
    in_custom_item = False
    current_item_lines = []
    current_item_id = None

    for line in lines:
        # Check if this is the start of a custom_item
        if re.match(r'^\s*#?<custom_item>', line):
            in_custom_item = True
            current_item_lines = [line]
            # Try to find the ID from the next description line
        elif in_custom_item:
            current_item_lines.append(line)

            # Check for description line to extract ID
            if 'description' in line and current_item_id is None:
                desc_match = re.search(r'description\s*:\s*"([^"]*)"', line)
                if desc_match:
                    desc = desc_match.group(1)
                    id_match = re.match(r'(\d+\.\d+)', desc)
                    if id_match:
                        current_item_id = id_match.group(1)

            # Check if this is the end of custom_item
            if re.match(r'^\s*#?</custom_item>', line):
                in_custom_item = False

                # Decide whether to uncomment or keep commented
                if current_item_id and current_item_id in baseline_ids:
                    # Uncomment all lines in this item
                    uncommented = []
                    for item_line in current_item_lines:
                        if item_line.strip().startswith('#'):
                            # Remove the leading # (before any whitespace)
                            uncommented.append(item_line.lstrip('#'))
                        else:
                            uncommented.append(item_line)
                    result_lines.extend(uncommented)
                else:
                    # Keep as is (commented or not, depending on source)
                    result_lines.extend(current_item_lines)

                current_item_lines = []
                current_item_id = None
        else:
            result_lines.append(line)

    return '\n'.join(result_lines)

# Configuration for each audit type
configs = {
    'PAFW': {
        'baseline': r'C:\PySC\TAP\actual_audit_inputs\HTH_Baseline_NETPAFW.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit',
    },
    'NXOS': {
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETNXOS_26091508.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\NXOS_all_audits.audit',
    },
    'IOS': {
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetIOS_AuditFile_26091508.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\IOS_all_audits.audit',
    },
    'ASA': {
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetASA_26091508.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\ASA_all_audits.audit',
    },
    'F5': {
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetF5_26091508.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\F5_all_audits.audit',
    },
    'RHEL': {
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit',
    },
    'MSWRK': {
        'baseline': r'C:\PySC\TAP\actual_audit_inputs\_unassigned\HTH_MSWRK_Baseline001.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\MSWRK_all_audits.audit',
    },
    'MSSRV': {
        'baseline': r'C:\PySC\TAP\tests\golden\gap_fixtures\MSSRV_Baseline.audit',
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\MSSRV_all_audits.audit',
    },
    'SQL': {
        'baseline': None,  # No baseline for SQL
        'consolidated': r'C:\PySC\TAP\Output\Consolidated\SQL_all_audits.audit',
    },
}

print("Fixing commented controls in consolidated audit files...")
print("=" * 60)

for audit_type, config in configs.items():
    baseline_path = config['baseline']
    consolidated_path = config['consolidated']

    if not baseline_path:
        print(f"[{audit_type}] SKIP - No baseline defined")
        continue

    baseline_path = Path(baseline_path)
    consolidated_path = Path(consolidated_path)

    # Check files exist
    if not baseline_path.exists():
        print(f"[{audit_type}] ERROR - Baseline not found: {baseline_path}")
        continue

    if not consolidated_path.exists():
        print(f"[{audit_type}] ERROR - Consolidated not found: {consolidated_path}")
        continue

    try:
        # Load baseline and extract control IDs
        with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
            baseline_content = f.read()

        baseline_ids = extract_control_ids(baseline_content)
        print(f"[{audit_type}] Baseline IDs found: {len(baseline_ids)}")

        if not baseline_ids:
            print(f"[{audit_type}] WARNING - No control IDs found in baseline")
            continue

        # Load consolidated file
        with open(consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
            consolidated_content = f.read()

        # Count before
        before_uncommented = len(re.findall(r'^\s*<custom_item>', consolidated_content, re.MULTILINE))
        before_commented = len(re.findall(r'^\s*#<custom_item>', consolidated_content, re.MULTILINE))

        # Fix commented controls
        fixed_content = uncomment_controls_by_id(consolidated_content, baseline_ids)

        # Count after
        after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))
        after_commented = len(re.findall(r'^\s*#<custom_item>', fixed_content, re.MULTILINE))

        # Write back if there were changes
        if fixed_content != consolidated_content:
            with open(consolidated_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"[{audit_type}] ✅ FIXED")
            print(f"         Before: {before_uncommented} uncommented, {before_commented} commented")
            print(f"         After:  {after_uncommented} uncommented, {after_commented} commented")
        else:
            print(f"[{audit_type}] ✓ No changes needed")
            print(f"         {after_uncommented} uncommented, {after_commented} commented")

    except Exception as e:
        print(f"[{audit_type}] ❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

print("=" * 60)
print("Done!")
