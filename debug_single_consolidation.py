#!/usr/bin/env python3
"""Debug single type consolidation"""

import sys
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator
from pathlib import Path
import re

try:
    output = []
    audit_type = 'PAFW'
    input_audit = r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit'
    baseline_path = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'
    cis_benchmark = r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit'
    output_file = r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits_debug.audit'

    output.append(f"Starting consolidation for {audit_type}")
    output.append(f"Input: {input_audit}")
    output.append(f"Baseline: {baseline_path}")
    output.append(f"CIS: {cis_benchmark}")

    # Create consolidator
    consolidator = AuditConsolidator(cis_benchmark, audit_type=audit_type)
    output.append(f"Created consolidator")

    # Load baseline
    output.append(f"Loading baseline controls...")
    result = consolidator.load_baseline_controls(baseline_path)
    output.append(f"Baseline load result: {result}")
    output.append(f"Controls loaded: {len(consolidator.used_controls)}")

    if consolidator.used_controls:
        sample_controls = list(consolidator.used_controls)[:3]
        for ctrl in sample_controls:
            output.append(f"  Sample: {ctrl}")

    # Consolidate
    output.append(f"Starting consolidation...")
    header = consolidator.consolidate(input_audit)

    if header:
        output.append(f"Consolidation successful")

        # Check results
        uncommented = 0
        commented = 0

        for item_content in consolidator.consolidated_items.values():
            if item_content.strip().startswith('#'):
                commented += 1
            else:
                uncommented += 1

        output.append(f"Results: {uncommented} uncommented, {commented} commented")
    else:
        output.append(f"Consolidation failed")

    # Write results
    with open(r'C:\PySC\TAP\debug_consolidation_output.txt', 'w') as f:
        for line in output:
            print(line)
            f.write(line + '\n')

except Exception as e:
    import traceback
    with open(r'C:\PySC\TAP\debug_consolidation_error.txt', 'w') as f:
        f.write(traceback.format_exc())
    print(f"Error written to file: {e}")
