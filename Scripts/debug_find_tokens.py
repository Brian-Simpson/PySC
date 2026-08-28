import pandas as pd
from pathlib import Path

files = [
    Path(r"C:\PySC\Audits\CIS_Cisco_IOS_12_v4.0.0_Level_1_custom_items.xlsx"),
    Path(r"C:\PySC\Audits\CIS_Microsoft_Azure_Foundations_v5.0.0_L1_custom_items.xlsx"),
    Path(r"C:\PySC\Audits\CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL_custom_items.xlsx"),
]

for f in files:
    if not f.exists():
        print(f"Missing: {f}")
        continue
    print('\n---', f)
    df = pd.read_excel(f, engine='openpyxl', dtype=str)
    df2 = df.fillna("")
    rows = []
    for i, row in df2.iterrows():
        for col in df2.columns:
            v = str(row[col])
            if '@' in v:
                rows.append((i, col, v[:200]))
    print(f"Found {len(rows)} cells with @ in {f.name}")
    for r in rows[:20]:
        print(r)
