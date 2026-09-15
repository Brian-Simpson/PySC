#!/usr/bin/env python3
"""
Properly fix consolidated audit files by using baseline structure as template
"""

import re
from pathlib import Path

def extract_control_id(description_line):
    """Extract ID from description line (e.g., '1.0000')"""
    match = re.search(r'"(\d+\.\d+)', description_line)
    return match.group(1) if match else None

def extract_all_controls(content):
    """Extract all control blocks from audit file"""
    # Split by custom_item tags - be careful with both commented and uncommented
    controls = []
    # Pattern to match control blocks, accounting for both commented and uncommented
    pattern = r'(#?)\s*<custom_item>.*?#?\s*</custom_item>'

    for match in re.finditer(pattern, content, re.DOTALL):
        control_text = match.group(0)
        controls.append(control_text)

    return controls

def extract_baseline_controls(baseline_path):
    """Extract control IDs from baseline file - these SHOULD be in the output"""
    baseline_ids = set()
    try:
        with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Find all description lines with control IDs
        for match in re.finditer(r'description\s*:\s*"(\d+\.\d+)', content):
            baseline_ids.add(match.group(1))
    except:
        pass

    return baseline_ids

def get_baseline_header_footer(baseline_path):
    """Extract header and footer from baseline file"""
    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Get everything before first <custom_item>
    match = re.search(r'^(.*?)(?=<custom_item>)', content, re.DOTALL)
    header = match.group(1) if match else ""

    # Get everything after last </custom_item>
    match = re.search(r'(</custom_item>.*)$', content, re.DOTALL)
    footer = match.group(1) if match else "</check_type>"

    return header, footer

def rebuild_consolidated(input_path, baseline_ids, header, footer):
    """Rebuild consolidated file with proper structure"""
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Extract all controls from input
    controls = []
    pattern = r'(#?)\s*<custom_item>.*?</custom_item>'

    for match in re.finditer(pattern, content, re.DOTALL):
        control_block = match.group(0)
        # Remove all # prefixes to get clean control
        clean_control = re.sub(r'^#\s*', '', control_block, flags=re.MULTILINE)

        # Extract ID from description
        desc_match = re.search(r'description\s*:\s*"(\d+\.\d+)', clean_control)
        control_id = desc_match.group(1) if desc_match else None

        controls.append({
            'id': control_id,
            'text': clean_control
        })

    # Build output
    output_lines = [header]

    for ctrl in controls:
        if ctrl['id'] and ctrl['id'] in baseline_ids:
            # Uncommented - from baseline
            output_lines.append(ctrl['text'])
        else:
            # Not in baseline - comment it out
            commented = '\n'.join('#' + line if line.strip() else line
                                 for line in ctrl['text'].split('\n'))
            output_lines.append(commented)

        # Add blank line between controls
        output_lines.append('')

    output_lines.append(footer)

    return '\n'.join(output_lines)

# Map of audit types to their paths
audits = {
    'PAFW': {
        'baseline': Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'),
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit'),
    },
    'RHEL': {
        'baseline': Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit'),
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\RHEL.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit'),
    },
    'MSSRV': {
        'baseline': Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_MSSRV_26091508.audit'),
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\MSSRV.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\MSSRV_all_audits.audit'),
    },
    'MSWRK': {
        'baseline': Path(r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_MSWRK_26091508.audit'),
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\MSWRK.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\MSWRK_all_audits.audit'),
    },
}

for audit_type, paths in audits.items():
    print(f"\nProcessing {audit_type}...")

    if not paths['baseline'].exists():
        print(f"  ❌ Baseline not found")
        continue
    if not paths['input'].exists():
        print(f"  ❌ Input not found")
        continue
    if not paths['output'].exists():
        print(f"  ❌ Output file not found")
        continue

    # Get baseline controls and structure
    baseline_ids = extract_baseline_controls(paths['baseline'])
    header, footer = get_baseline_header_footer(paths['baseline'])

    print(f"  Baseline IDs: {len(baseline_ids)}")

    # Count before
    with open(paths['output'], 'r', encoding='utf-8', errors='ignore') as f:
        before = f.read()
    before_uncommented = len(re.findall(r'^\s*<custom_item>', before, re.MULTILINE))
    before_commented = len(re.findall(r'^\s*#<custom_item>', before, re.MULTILINE))

    # Rebuild
    fixed = rebuild_consolidated(paths['input'], baseline_ids, header, footer)

    # Count after
    after_uncommented = len(re.findall(r'^\s*<custom_item>', fixed, re.MULTILINE))
    after_commented = len(re.findall(r'^\s*#<custom_item>', fixed, re.MULTILINE))

    # Write
    with open(paths['output'], 'w', encoding='utf-8') as f:
        f.write(fixed)

    print(f"  Before: {before_uncommented} uncommented, {before_commented} commented")
    print(f"  After:  {after_uncommented} uncommented, {after_commented} commented")
    print(f"  ✅ Fixed")

print("\n" + "="*60)
print("Done!")
print("="*60)
