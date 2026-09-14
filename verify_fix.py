#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator, extract_controls_to_sheet
from pathlib import Path

print("Running consolidation with latest code...")
print("This should fully comment controls including opening tags\n")

audit_type = 'PAFW'
input_audit = r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit'
cis_benchmark = r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit'
output_file = r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits_test.audit'
controls_catalog = r'C:\PySC\TAP\Output\Processed\Normalized\Unique_Controls_Catalog_26091415.xlsx'

consolidator = AuditConsolidator(cis_benchmark)
consolidator.load_controls_catalog(controls_catalog)

header = consolidator.consolidate(input_audit)
if header:
    consolidator.write_consolidated(Path(output_file), header)
    print(f"✅ Consolidated {len(consolidator.consolidated_items)} controls\n")

    # Check the first 50 lines for proper commenting
    with open(output_file, 'r') as f:
        lines = f.readlines()[:50]

    print("First 50 lines of output:")
    for i, line in enumerate(lines, 1):
        print(f"{i:3}: {line.rstrip()}")

    # Check if opening tags are commented
    if any(line.strip().startswith('#<custom_item>') for line in lines):
        print("\n✅ Opening tags ARE properly commented!")
    else:
        print("\n❌ Opening tags are NOT commented")
