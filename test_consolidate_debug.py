#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator
from pathlib import Path

print("Testing consolidation with debug output...")

audit_type = 'PAFW'
input_audit = r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit'
cis_benchmark = r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit'
output_file = r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits_test.audit'
controls_catalog = r'C:\PySC\TAP\Output\Processed\Normalized\Unique_Controls_Catalog_26091415.xlsx'

# Run consolidation
consolidator = AuditConsolidator(cis_benchmark, audit_type='PAFW')
consolidator.load_controls_catalog(controls_catalog)

header = consolidator.consolidate(input_audit)
if header:
    consolidator.write_consolidated(Path(output_file), header)
    print(f"✅ Consolidated {len(consolidator.consolidated_items)} controls")

    # Check the first 50 lines for proper commenting
    with open(output_file, 'r') as f:
        lines = f.readlines()[:50]

    print("\n=== First 50 lines of output ===")
    for i, line in enumerate(lines, 1):
        print(f"{i:3}: {line.rstrip()}")

    # Check if opening tags are commented
    commented_count = sum(1 for line in lines if line.strip().startswith('#<custom_item>'))
    uncommented_count = sum(1 for line in lines if line.strip().startswith('<custom_item>') and not line.strip().startswith('#'))

    print(f"\n✅ Opening tags PROPERLY commented: {commented_count}")
    print(f"❌ Opening tags NOT commented: {uncommented_count}")
else:
    print("❌ Consolidation failed")
