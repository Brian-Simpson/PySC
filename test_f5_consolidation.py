#!/usr/bin/env python3
"""Test F5 consolidation with debug output"""

import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, r'C:\PySC\TAP\scripts')
from audit_consolidator import AuditConsolidator

timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

config = {
    'input': r'C:\PySC\TAP\Output\Processed\For_Gap\F5.audit',
    'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetF5_26091508.audit',
    'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_F5_Networks_Benchmark_v1.0.0_L1.audit',
    'output': r'C:\PySC\TAP\Output\Consolidated\F5_test_{}.audit',
}

output_file = open(r'C:\PySC\TAP\f5_debug.txt', 'w')

output_file.write("F5 Consolidation Debug\n")
output_file.write("=======================\n\n")

try:
    input_path = Path(config['input'])
    baseline_path = Path(config['baseline'])
    output_path = Path(config['output'].format(timestamp))
    cis_path = config['cis']

    consolidator = AuditConsolidator(cis_path, audit_type='F5')

    output_file.write("Loading baseline controls...\n")
    baseline_loaded = consolidator.load_baseline_controls(str(baseline_path))
    output_file.write(f"  Baseline loaded: {baseline_loaded}\n")
    output_file.write(f"  Used controls: {len(consolidator.used_controls)}\n\n")

    output_file.write("Consolidating input...\n")
    header = consolidator.consolidate(str(input_path))

    output_file.write(f"  Header: {header}\n")
    output_file.write(f"  Consolidated items: {len(consolidator.consolidated_items)}\n\n")

    output_file.write("Writing output...\n")
    consolidator.write_consolidated(output_path, header)

    output_file.write(f"  Output file: {output_path}\n\n")

    # Check output
    with open(output_path, 'r') as f:
        content = f.read()

    opens = content.count('<custom_item>')
    closes = content.count('</custom_item>')

    output_file.write("Output verification:\n")
    output_file.write(f"  Opening tags: {opens}\n")
    output_file.write(f"  Closing tags: {closes}\n")
    output_file.write(f"  Balance: {opens == closes}\n")

except Exception as e:
    output_file.write(f"ERROR: {e}\n")
    import traceback
    output_file.write(traceback.format_exc())

output_file.close()
print("Debug output written to f5_debug.txt")
