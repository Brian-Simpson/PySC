import sys
from pathlib import Path
sys.path.insert(0, r"C:\PySC")
import audit_custom_items_to_excel as a
p = Path(r"C:\PySC\Audits\CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit")
text = p.read_text(encoding='utf-8', errors='replace')
vars_map = a.parse_variables(text)
print('Found variables:', len(vars_map))
for k,v in sorted(vars_map.items()):
    print(k, '=>', v)
