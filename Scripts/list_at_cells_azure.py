import pandas as pd
from pathlib import Path

p = Path(r"C:\PySC\Audits\combined_custom_items.xlsx")
sheet = 'CIS_Microsoft_Azure_Foundations'
df = pd.read_excel(p, sheet_name=sheet, dtype=str)
rows = []
for i, row in df.iterrows():
    for col in df.columns:
        v = str(row[col]) if pd.notna(row[col]) else ''
        if '@' in v:
            rows.append((i, col, v[:300]))

print('Found', len(rows), 'cells with @')
for r in rows[:50]:
    print(r)
