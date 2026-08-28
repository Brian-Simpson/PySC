import re
from pathlib import Path
import pandas as pd

p = Path(r"C:\PySC\Audits\combined_custom_items.xlsx")
if not p.exists():
    print('Combined file missing')
    raise SystemExit(1)

sheet = 'CIS_Microsoft_Azure_Foundations'
df = pd.read_excel(p, sheet_name=sheet, dtype=str)
regex = re.compile(r'@([A-Za-z0-9_]+)@')
found = set()
for col in df.columns:
    for v in df[col].fillna(''):
        for m in regex.finditer(str(v)):
            found.add(m.group(0))

print('Distinct tokens found:', len(found))
for t in sorted(found):
    print(t)
