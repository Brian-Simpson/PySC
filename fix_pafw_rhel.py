#!/usr/bin/env python3
"""
Fix commented controls - with detailed logging to file
"""

import re
from pathlib import Path

log_output = []

def log(msg):
    log_output.append(msg)
    print(msg)

def extract_control_ids(content):
    """Extract all control IDs from audit file content"""
    ids = set()
    descriptions = re.findall(r'description\s*:\s*"([^"]*)"', content)
    for desc in descriptions:
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
        if re.match(r'^\s*#?<custom_item>', line):
            in_custom_item = True
            current_item_lines = [line]
        elif in_custom_item:
            current_item_lines.append(line)

            if 'description' in line and current_item_id is None:
                desc_match = re.search(r'description\s*:\s*"([^"]*)"', line)
                if desc_match:
                    desc = desc_match.group(1)
                    id_match = re.match(r'(\d+\.\d+)', desc)
                    if id_match:
                        current_item_id = id_match.group(1)

            if re.match(r'^\s*#?</custom_item>', line):
                in_custom_item = False

                if current_item_id and current_item_id in baseline_ids:
                    uncommented = []
                    for item_line in current_item_lines:
                        if item_line.strip().startswith('#'):
                            uncommented.append(item_line.lstrip('#'))
                        else:
                            uncommented.append(item_line)
                    result_lines.extend(uncommented)
                else:
                    result_lines.extend(current_item_lines)

                current_item_lines = []
                current_item_id = None
        else:
            result_lines.append(line)

    return '\n'.join(result_lines)

# Process PAFW
log("Processing PAFW...")
try:
    baseline_path = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit')
    consolidated_path = Path(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit')

    if not baseline_path.exists():
        log(f"  ERROR - Baseline not found")
    elif not consolidated_path.exists():
        log(f"  ERROR - Consolidated not found")
    else:
        with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
            baseline_content = f.read()

        baseline_ids = extract_control_ids(baseline_content)
        log(f"  Baseline IDs: {len(baseline_ids)}")
        log(f"  Sample IDs: {sorted(baseline_ids)[:5]}")

        with open(consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
            consolidated_content = f.read()

        before_uncommented = len(re.findall(r'^\s*<custom_item>', consolidated_content, re.MULTILINE))
        before_commented = len(re.findall(r'^\s*#<custom_item>', consolidated_content, re.MULTILINE))
        log(f"  Before: {before_uncommented} uncommented, {before_commented} commented")

        fixed_content = uncomment_controls_by_id(consolidated_content, baseline_ids)

        after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))
        after_commented = len(re.findall(r'^\s*#<custom_item>', fixed_content, re.MULTILINE))
        log(f"  After: {after_uncommented} uncommented, {after_commented} commented")

        with open(consolidated_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        log(f"  ✅ Written to disk")

except Exception as e:
    log(f"  ❌ Exception: {e}")
    import traceback
    log(traceback.format_exc())

# Process RHEL
log("\nProcessing RHEL...")
try:
    baseline_path = Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit')
    consolidated_path = Path(r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit')

    if not baseline_path.exists():
        log(f"  ERROR - Baseline not found")
    elif not consolidated_path.exists():
        log(f"  ERROR - Consolidated not found")
    else:
        with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
            baseline_content = f.read()

        baseline_ids = extract_control_ids(baseline_content)
        log(f"  Baseline IDs: {len(baseline_ids)}")
        log(f"  Sample IDs: {sorted(baseline_ids)[:5]}")

        with open(consolidated_path, 'r', encoding='utf-8', errors='ignore') as f:
            consolidated_content = f.read()

        before_uncommented = len(re.findall(r'^\s*<custom_item>', consolidated_content, re.MULTILINE))
        before_commented = len(re.findall(r'^\s*#<custom_item>', consolidated_content, re.MULTILINE))
        log(f"  Before: {before_uncommented} uncommented, {before_commented} commented")
        log(f"  File size: {len(consolidated_content)} bytes")

        if before_uncommented + before_commented == 0:
            log(f"  WARNING: No <custom_item> blocks found in file!")

        fixed_content = uncomment_controls_by_id(consolidated_content, baseline_ids)

        after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed_content, re.MULTILINE))
        after_commented = len(re.findall(r'^\s*#<custom_item>', fixed_content, re.MULTILINE))
        log(f"  After: {after_uncommented} uncommented, {after_commented} commented")

        with open(consolidated_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        log(f"  ✅ Written to disk")

except Exception as e:
    log(f"  ❌ Exception: {e}")
    import traceback
    log(traceback.format_exc())

# Write log
with open(r'C:\PySC\TAP\fix_controls_log.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(log_output))

log("\nLog written to fix_controls_log.txt")
