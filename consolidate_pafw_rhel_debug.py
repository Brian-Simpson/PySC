#!/usr/bin/env python3
"""
Consolidate all audit types using baseline controls - WITH ERROR LOGGING
"""

import sys
import re
from pathlib import Path

sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator

log_file = r'C:\PySC\TAP\consolidation_debug.log'

def log(msg):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(msg + '\n')
    print(msg)

# Clear log
open(log_file, 'w').close()

log(f"Starting consolidation...")

audit_configs = {
    'PAFW': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits.audit',
    },
    'RHEL': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\RHEL.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_RedHat_Enterprise_Linux_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits.audit',
    },
}

for audit_type, config in audit_configs.items():
    try:
        log(f"\n[{audit_type}] Processing...")

        input_path = Path(config['input'])
        baseline_path = Path(config['baseline']) if config['baseline'] else None
        output_path = Path(config['output'])

        cis_pattern = config['cis']
        if '*' in cis_pattern:
            import glob
            cis_files = glob.glob(cis_pattern)
            if cis_files:
                cis_path = cis_files[0]
            else:
                log(f"  CIS not found: {cis_pattern}")
                continue
        else:
            cis_path = cis_pattern

        log(f"  Input: {input_path.exists()}")
        log(f"  Baseline: {baseline_path.exists() if baseline_path else 'N/A'}")
        log(f"  CIS: {Path(cis_path).exists()}")

        if not input_path.exists():
            log(f"  ERROR: Input not found")
            continue

        if baseline_path and not baseline_path.exists():
            log(f"  ERROR: Baseline not found")
            baseline_path = None

        if not Path(cis_path).exists():
            log(f"  ERROR: CIS not found")
            continue

        log(f"  Creating consolidator...")
        consolidator = AuditConsolidator(cis_path, audit_type=audit_type)

        if baseline_path:
            log(f"  Loading baseline...")
            result = consolidator.load_baseline_controls(str(baseline_path))
            log(f"    Result: {result}, IDs loaded: {len(consolidator.used_controls)}")

        log(f"  Starting consolidation...")
        header = consolidator.consolidate(str(input_path))

        if header:
            log(f"  Writing output...")
            consolidator.write_consolidated(output_path, header)
            log(f"  SUCCESS: {len(consolidator.consolidated_items)} items")
        else:
            log(f"  ERROR: Consolidation returned None")

    except Exception as e:
        import traceback
        log(f"  EXCEPTION: {e}")
        log(f"  {traceback.format_exc()}")

log(f"\nDone")
