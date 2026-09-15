#!/usr/bin/env python3
"""Check F5 input file for control structure issues"""

import re
from pathlib import Path

input_file = r'C:\PySC\TAP\Output\Processed\For_Gap\F5.audit'
output_file = r'C:\PySC\TAP\check_f5_structure.txt'

with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Try to extract controls with the same regex used in consolidator
pattern = r'<custom_item>.*?</custom_item>'
controls = re.findall(pattern, content, re.DOTALL)

with open(output_file, 'w') as out:
    out.write(f"F5 Input File Structure Analysis\n")
    out.write(f"================================\n\n")

    out.write(f"Total controls extracted: {len(controls)}\n")
    out.write(f"Total open tags in file: {content.count('<custom_item>')}\n")
    out.write(f"Total close tags in file: {content.count('</custom_item>')}\n\n")

    # Check each control
    malformed = 0
    for i, ctrl in enumerate(controls):
        opens = ctrl.count('<custom_item>')
        closes = ctrl.count('</custom_item>')
        if opens != 1 or closes != 1:
            malformed += 1
            out.write(f"Control {i+1}: MALFORMED - Opens: {opens}, Closes: {closes}\n")
            out.write(f"  First 100 chars: {ctrl[:100]}\n")
            out.write(f"  Last 100 chars: {ctrl[-100:]}\n\n")

    out.write(f"\nTotal malformed controls: {malformed}\n")

    # Check for loose closing tags
    # Remove all matched control blocks and see what's left
    content_without_controls = content
    for ctrl in controls:
        content_without_controls = content_without_controls.replace(ctrl, '', 1)

    loose_closes = content_without_controls.count('</custom_item>')
    loose_opens = content_without_controls.count('<custom_item>')

    out.write(f"\nAfter removing all matched controls:\n")
    out.write(f"  Remaining opens: {loose_opens}\n")
    out.write(f"  Remaining closes: {loose_closes}\n")

print("Analysis complete - output written to check_f5_structure.txt")
