#!/usr/bin/env python3
"""
Restore all network audits from input files - simple consolidation without baseline filtering
"""

import sys
sys.path.insert(0, r'C:\PySC\TAP\scripts')

from pathlib import Path
from audit_consolidator import consolidate

audits = {
    'ASA': {
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\ASA.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\ASA_all_audits.audit'),
    },
    'F5': {
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\F5.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\F5_all_audits.audit'),
    },
    'IOS': {
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\IOS.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\IOS_all_audits.audit'),
    },
    'NXOS': {
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\NXOS.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\NXOS_all_audits.audit'),
    },
    'SQL': {
        'input': Path(r'C:\PySC\TAP\Output\Processed\For_Gap\SQL.audit'),
        'output': Path(r'C:\PySC\TAP\Output\Consolidated\SQL_all_audits.audit'),
    },
}

print("Restoring network audits to clean state...\n")

for audit_type, paths in audits.items():
    print(f"Processing {audit_type}...")

    if not paths['input'].exists():
        print(f"  ❌ Input not found")
        continue
    if not paths['output'].exists():
        print(f"  ❌ Output not found")
        continue

    try:
        consolidate(paths['input'], paths['output'], baseline_ids=None)
        print(f"  ✅ Restored")
    except Exception as e:
        print(f"  ❌ Error: {e}")

print("\n" + "="*60)
print("Done!")
print("="*60)
