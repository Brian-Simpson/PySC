#!/usr/bin/env python3
"""
Consolidate all audit types using baseline controls to uncomment
"""

import sys
import re
from pathlib import Path
from datetime import datetime

sys.path.insert(0, r'C:\PySC\TAP')

from scripts.audit_consolidator import AuditConsolidator

# Generate timestamp for output filenames
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

# Mapping of audit type to (input file, baseline file, cis benchmark)
audit_configs = {
    'PAFW': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\PAFW.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits_{}.audit',
    },
    'NXOS': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\NXOS.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETNXOS_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Cisco_NX-OS_v*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\NXOS_all_audits_{}.audit',
    },
    'IOS': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\IOS.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetIOS_AuditFile_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Cisco_IOS_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\IOS_all_audits_{}.audit',
    },
    'ASA': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\ASA.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetASA_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Cisco_ASA_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\ASA_all_audits_{}.audit',
    },
    'F5': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\F5.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NetF5_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_F5_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\F5_all_audits_{}.audit',
    },
    'RHEL': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\RHEL.audit',
        'baseline': r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_RHEL_26091508.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_RedHat_Enterprise_Linux_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\RHEL_all_audits_{}.audit',
    },
    'MSWRK': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\MSWRK.audit',
        'baseline': r'C:\PySC\TAP\actual_audit_inputs\_unassigned\HTH_MSWRK_Baseline001.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Microsoft_Windows_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\MSWRK_all_audits_{}.audit',
    },
    'MSSRV': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\MSSRV.audit',
        'baseline': r'C:\PySC\TAP\tests\golden\gap_fixtures\MSSRV_Baseline.audit',
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Microsoft_Windows_Server_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\MSSRV_all_audits_{}.audit',
    },
    'SQL': {
        'input': r'C:\PySC\TAP\Output\Processed\For_Gap\SQL.audit',
        'baseline': None,
        'cis': r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Microsoft_SQL_Server_*.audit',
        'output': r'C:\PySC\TAP\Output\Consolidated\SQL_all_audits_{}.audit',
    },
}

results = []

for audit_type, config in audit_configs.items():
    input_path = Path(config['input'])
    baseline_path = Path(config['baseline']) if config['baseline'] else None
    output_path = Path(config['output'].format(timestamp))

    cis_pattern = config['cis']
    if '*' in cis_pattern:
        import glob
        cis_files = glob.glob(cis_pattern)
        if cis_files:
            cis_path = cis_files[0]
        else:
            results.append(f"❌ [{audit_type}] CIS not found")
            continue
    else:
        cis_path = cis_pattern

    if not input_path.exists():
        results.append(f"❌ [{audit_type}] Input not found")
        continue

    if baseline_path and not baseline_path.exists():
        results.append(f"⚠️  [{audit_type}] Baseline not found - all controls will be commented")
        baseline_path = None

    if not Path(cis_path).exists():
        results.append(f"❌ [{audit_type}] CIS not found")
        continue

    try:
        consolidator = AuditConsolidator(cis_path, audit_type=audit_type)
        baseline_loaded = False
        if baseline_path:
            baseline_loaded = consolidator.load_baseline_controls(str(baseline_path))
            results.append(f"   Debug: baseline_loaded={baseline_loaded}, used_controls={len(consolidator.used_controls)}")

        header = consolidator.consolidate(str(input_path))
        if header:
            consolidator.write_consolidated(output_path, header)

            with open(output_path, 'r') as f:
                content = f.read()
            uncommented = len(re.findall(r'^\s*<custom_item>', content, re.MULTILINE)) - len(re.findall(r'^\s*#<custom_item>', content, re.MULTILINE))
            total = len(re.findall(r'<custom_item>', content, re.DOTALL))

            results.append(f"✅ [{audit_type}] {uncommented}/{total} controls uncommented")
        else:
            results.append(f"❌ [{audit_type}] Consolidation failed")

    except Exception as e:
        results.append(f"❌ [{audit_type}] Error: {str(e)[:60]}")

# Ensure timestamped copies exist for all files
print("\nEnsuring all consolidated files have timestamped versions...")
for audit_type in audit_configs.keys():
    output_base = audit_configs[audit_type]['output'].format(timestamp)
    output_path = Path(output_base)

    if not output_path.exists():
        # Try to copy from non-timestamped version if it exists
        non_ts_path = Path(str(output_base).replace(f"_{timestamp}", ""))
        if non_ts_path.exists():
            import shutil
            try:
                shutil.copy2(str(non_ts_path), str(output_path))
                print(f"  ✅ Created timestamped {audit_type}: {output_path.name}")
            except Exception as e:
                print(f"  ❌ Failed to create timestamped {audit_type}: {e}")

print("\n" + "="*60)
for line in results:
    print(line)
print("="*60)
