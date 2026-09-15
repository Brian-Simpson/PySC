#!/usr/bin/env python3
"""
Remove orphaned closing tags from consolidated audit files
"""

import re
from pathlib import Path

def fix_orphaned_tags(file_path):
    """Remove orphaned </custom_item> tags"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    lines = content.split('\n')
    fixed_lines = []
    in_control = False
    orphaned_removed = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track if we're inside a control
        if stripped.startswith('<custom_item>') or stripped.startswith('#<custom_item>'):
            in_control = True
            fixed_lines.append(line)
        elif stripped.startswith('</custom_item>') or stripped.startswith('#</custom_item>'):
            if in_control:
                in_control = False
                fixed_lines.append(line)
            else:
                # Skip orphaned closing tag
                print(f"  Removed orphaned tag at line {i+1}")
                orphaned_removed += 1
        else:
            fixed_lines.append(line)

    if orphaned_removed > 0:
        fixed_content = '\n'.join(fixed_lines)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        return orphaned_removed

    return 0

# Process all consolidated audit files
consolidated_dir = Path(r'C:\PySC\TAP\Output\Consolidated')
files = sorted(consolidated_dir.glob('*_all_audits_*.audit'))

print("Fixing orphaned tags in consolidated audit files...")
print("=" * 60)

for file_path in files:
    removed = fix_orphaned_tags(file_path)
    if removed > 0:
        print(f"✅ {file_path.name}: removed {removed} orphaned tag(s)")
    else:
        print(f"✅ {file_path.name}: no orphaned tags")

print("\n" + "=" * 60)
print("Done!")
