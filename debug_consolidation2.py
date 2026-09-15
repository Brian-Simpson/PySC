#!/usr/bin/env python3
"""Debug consolidation - check baseline loading - write to file"""

import sys
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator
from pathlib import Path

output = []

# Test PAFW
output.append("Testing PAFW consolidation...")
consolidator = AuditConsolidator(
    r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit',
    audit_type='PAFW'
)

baseline_path = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'
output.append(f"Baseline exists: {Path(baseline_path).exists()}")

if Path(baseline_path).exists():
    try:
        result = consolidator.load_baseline_controls(baseline_path)
        output.append(f"Baseline loaded successfully: {result}")
        output.append(f"Controls loaded: {len(consolidator.used_controls)}")
        if consolidator.used_controls:
            sample = list(consolidator.used_controls)[:3]
            output.append(f"Sample controls: {sample}")
    except Exception as e:
        output.append(f"❌ Error loading: {e}")
else:
    output.append(f"❌ Baseline file not found")

# Write results
with open(r'C:\PySC\TAP\debug_output.txt', 'w') as f:
    for line in output:
        print(line)
        f.write(line + '\n')
