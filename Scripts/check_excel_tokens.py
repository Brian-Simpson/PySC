import glob
import pandas as pd
from pathlib import Path

files = sorted(Path(r"C:\PySC\Audits").glob("*_custom_items.xlsx"))
if not files:
    print("No generated Excel files found")
    raise SystemExit(1)

for f in files:
    try:
        df = pd.read_excel(f, engine='openpyxl', dtype=str)
    except Exception as e:
        print(f"ERROR reading {f}: {e}")
        continue
    contains_at = df.fillna("").astype(str).apply(lambda col: col.str.contains('@')).any().any()
    total_at = df.fillna("").astype(str).applymap(lambda v: v.count('@')).sum().sum()
    print(f"{f}: contains @ tokens? {contains_at}; total @ occurrences: {int(total_at)}")
