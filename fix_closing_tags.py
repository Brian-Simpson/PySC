#!/usr/bin/env python3
"""
Add missing closing tags to consolidated audit files
"""

from pathlib import Path
import re

files_to_fix = [
    Path(r'C:\PySC\TAP\Output\Consolidated\ASA_all_audits.audit'),
    Path(r'C:\PySC\TAP\Output\Consolidated\F5_all_audits.audit'),
    Path(r'C:\PySC\TAP\Output\Consolidated\IOS_all_audits.audit'),
    Path(r'C:\PySC\TAP\Output\Consolidated\MSSRV_all_audits.audit'),
    Path(r'C:\PySC\TAP\Output\Consolidated\MSWRK_all_audits.audit'),
]

for file_path in files_to_fix:
    if not file_path.exists():
        print(f"Skipping {file_path.name} - not found")
        continue

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    if content.rstrip().endswith('</check_type>'):
        print(f"✅ {file_path.name} - already has closing tag")
        continue

    # Add closing tag if missing
    if not content.rstrip().endswith('</check_type>'):
        if content.rstrip().endswith('>'):
            content = content.rstrip() + '\n</check_type>\n'
        else:
            content = content.rstrip() + '\n</check_type>\n'

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✅ {file_path.name} - added closing tag")
    else:
        print(f"✅ {file_path.name} - closing tag OK")

print("\nDone!")
