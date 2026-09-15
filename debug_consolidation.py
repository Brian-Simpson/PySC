#!/usr/bin/env python3
"""Debug consolidation - check baseline loading"""

import sys
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator
from pathlib import Path

# Test PAFW
print("Testing PAFW consolidation...")
consolidator = AuditConsolidator(
    r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit',
    audit_type='PAFW'
)

baseline_path = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'
print(f"Baseline exists: {Path(baseline_path).exists()}")

if Path(baseline_path).exists():
    result = consolidator.load_baseline_controls(baseline_path)
    print(f"Baseline loaded successfully: {result}")
    print(f"Controls loaded: {len(consolidator.used_controls)}")
    if consolidator.used_controls:
        print(f"Sample controls: {list(consolidator.used_controls)[:3]}")
else:
    print(f"❌ Baseline file not found")
