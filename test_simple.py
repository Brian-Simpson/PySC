#!/usr/bin/env python3
import sys
import re
sys.path.insert(0, r'C:\PySC\TAP')

try:
    from scripts.audit_consolidator import AuditConsolidator, AuditItem
    from pathlib import Path

    baseline_path = r'C:\PySC\TAP\Output\Processed\Normalized\HTH_Baseline_NETPAFW_26091508.audit'

    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    items = re.findall(r'<custom_item>.*?</custom_item>', content, re.DOTALL)

    results = [f"Found {len(items)} items in baseline\n"]

    baseline_ids = set()
    for item in items[:3]:
        item_obj = AuditItem(item)
        if item_obj.description:
            id_match = re.match(r'(\d+\.\d+)', item_obj.description)
            if id_match:
                baseline_ids.add(id_match.group(1))
                results.append(f"ID: {id_match.group(1)} - {item_obj.description[:60]}")

    results.append(f"\nBaseline IDs: {baseline_ids}")

    with open(r'C:\PySC\TAP\test_output.txt', 'w') as f:
        for line in results:
            f.write(line + '\n')
            print(line)

except Exception as e:
    with open(r'C:\PySC\TAP\test_error.txt', 'w') as f:
        f.write(f"Error: {e}\n")
        import traceback
        f.write(traceback.format_exc())
    print(f"Error written to file")
