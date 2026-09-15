#!/usr/bin/env python3
import sys
import re
sys.path.insert(0, r'C:\PySC\TAP')

# Read the consolidated file and extract a commented control
with open(r'C:\PySC\TAP\Output\Consolidated\PAFW_all_audits_test.audit', 'r') as f:
    content = f.read()

# Find commented controls (with content commented but opening tag not)
problematic = re.findall(r'<custom_item>.*?#   type.*?</custom_item>', content, re.DOTALL)

if problematic:
    first = problematic[0]
    lines = first.split('\n')
    print(f"Found problematic control with {len(lines)} lines:")
    print(f"Line 0: {repr(lines[0])}")
    print(f"Line 1: {repr(lines[1])}")
    print(f"Line -1: {repr(lines[-1])}")
    print(f"\nFirst 300 chars:")
    print(repr(first[:300]))

    # Now test the comment_out_control function on this
    from scripts.audit_consolidator import AuditConsolidator
    consolidator = AuditConsolidator(r'C:\PySC\TAP\Output\Processed\Normalized\CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit')

    print("\n\nTesting comment_out_control on this item:")
    result = consolidator.comment_out_control(first)
    result_lines = result.split('\n')
    print(f"Result line 0: {repr(result_lines[0])}")
    print(f"Result line 1: {repr(result_lines[1])}")
    print(f"Result line -1: {repr(result_lines[-1])}")
