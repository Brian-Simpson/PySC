from pathlib import Path
import pandas as pd

p = Path(r"C:\PySC\Audits\combined_custom_items.xlsx")
if not p.exists():
    print('Combined file missing:', p)
    raise SystemExit(1)

xls = pd.ExcelFile(p, engine='openpyxl')
total = 0
for sheet in xls.sheet_names:
    df = pd.read_excel(xls, sheet_name=sheet, dtype=str)
    count = df.fillna("").astype(str).applymap(lambda v: v.count('@')).sum().sum()
    print(f"{sheet}: @{int(count)} occurrences")
    total += int(count)
print('Total @ occurrences in combined workbook:', total)
