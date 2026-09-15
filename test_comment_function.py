#!/usr/bin/env python3
"""Test the comment_out_control function"""

import sys
sys.path.insert(0, r'C:\PySC\TAP\scripts')

from audit_consolidator import AuditConsolidator

# Redirect output to file
output_file = r'C:\PySC\TAP\test_output.txt'
with open(output_file, 'w') as f:
    # Create a test consolidator
    consolidator = AuditConsolidator(r'C:\PySC\TAP\Output\Processed\Normalized\CIS_F5_Networks_Benchmark_v1.0.0_L1.audit')

    # Test control block
    test_control = """<custom_item>
  type             : REST_CHECK
  description      : "1.0000 - F5 - Test Control"
  info             : "Test info"
  expect           : "Test"
  f5_command       : "/tm/ltm/pool"
</custom_item>"""

    f.write("Original control:\n")
    f.write(test_control)
    f.write("\n\n" + "="*60 + "\n\n")

    commented = consolidator.comment_out_control(test_control)
    f.write("After comment_out_control():\n")
    f.write(commented)
    f.write("\n\n" + "="*60 + "\n\n")

    # Check if both tags are commented
    lines = commented.split('\n')
    open_commented = any('#<custom_item>' in line for line in lines)
    close_commented = any('#</custom_item>' in line for line in lines)
    open_uncommented = any('<custom_item>' in line and '#' not in line for line in lines)
    close_uncommented = any('</custom_item>' in line and '#' not in line for line in lines)

    f.write("Analysis:\n")
    f.write(f"  Opening tag commented: {open_commented}\n")
    f.write(f"  Closing tag commented: {close_commented}\n")
    f.write(f"  Opening tag uncommented: {open_uncommented}\n")
    f.write(f"  Closing tag uncommented: {close_uncommented}\n")

    if open_commented and close_commented and not open_uncommented and not close_uncommented:
        f.write("\n✅ PASS: Both tags properly commented\n")
    else:
        f.write("\n❌ FAIL: Tags not properly commented\n")

print("Test complete - output written to test_output.txt")

