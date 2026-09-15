#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator

audit_types = [
    ('PAFW', r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit'),
    ('NXOS', r'C:\PySC\TAP\Output\Processed\For_Gap\NXOS.audit'),
    ('IOS', r'C:\PySC\TAP\Output\Processed\For_Gap\IOS.audit'),
]

cis_base = r'C:\PySC\TAP\Output\Processed\Normalized'
cis_patterns = {
    'PAFW': 'CIS_Palo_Alto_Firewall_11_Benchmark_v*.audit',
    'NXOS': 'CIS_Cisco_NX-OS_v*.audit',
    'IOS': 'CIS_Cisco_IOS_*.audit',
}

catalog = r'C:\PySC\TAP\Output\Processed\Normalized\Unique_Controls_Catalog_26091416.xlsx'
console_log = r'C:\PySC\TAP\consolidation_test.log'

log_output = []

for audit_type, input_file in audit_types:
    if not Path(input_file).exists():
        log_output.append(f"[{audit_type}] SKIP - input file not found")
        continue

    # Find CIS benchmark
    import glob
    pattern = f"{cis_base}/{cis_patterns[audit_type]}"
    cis_files = glob.glob(pattern)
    if not cis_files:
        log_output.append(f"[{audit_type}] SKIP - CIS benchmark not found")
        continue

    cis_file = cis_files[0]
    output_file = f'C:/PySC/TAP/Output/Consolidated/{audit_type}_all_audits_test.audit'

    try:
        log_output.append(f"[{audit_type}] Processing...")
        consolidator = AuditConsolidator(cis_file, audit_type=audit_type)
        consolidator.load_controls_catalog(catalog)

        header = consolidator.consolidate(input_file)
        if header:
            consolidator.write_consolidated(Path(output_file), header)

            # Count properly commented items
            with open(output_file, 'r') as f:
                content = f.read()

            import re
            commented = len(re.findall(r'^\s*#<custom_item>', content, re.MULTILINE))
            uncommented = len(re.findall(r'^\s*<custom_item>\s*\n\s*[^#]', content, re.MULTILINE))

            log_output.append(f"[{audit_type}] ✅ DONE - {len(consolidator.consolidated_items)} items, {commented} properly commented, {uncommented} improperly commented")
        else:
            log_output.append(f"[{audit_type}] ❌ Failed to consolidate")
    except Exception as e:
        log_output.append(f"[{audit_type}] ❌ Error: {e}")

# Write results
with open(console_log, 'w') as f:
    for line in log_output:
        print(line)
        f.write(line + '\n')

print(f"\nResults saved to {console_log}")
