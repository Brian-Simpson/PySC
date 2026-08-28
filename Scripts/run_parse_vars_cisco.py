import sys
from pathlib import Path
sys.path.insert(0, r"C:\PySC")
import audit_custom_items_to_excel as a
p = Path(r"C:\PySC\Audits\CIS_Cisco_IOS_12_v4.0.0_Level_1.audit")
text = p.read_text(encoding='utf-8', errors='replace')
vars_map = a.parse_variables(text)
print('Found variables:', len(vars_map))
for k,v in sorted(vars_map.items()):
    print(k, '=>', v)
