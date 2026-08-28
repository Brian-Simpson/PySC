import sys
from pathlib import Path
sys.path.insert(0, r"C:\PySC")
import audit_custom_items_to_excel as a
p = Path(r"C:\PySC\Audits\CIS_Cisco_IOS_12_v4.0.0_Level_1.audit")
text = p.read_text(encoding='utf-8', errors='replace')
vars_map = a.parse_variables(text)
blocks = a.parse_custom_items(text)
import re
token_pat = re.compile(r'@([A-Za-z0-9_]+)@')
remaining = []
for i,b in enumerate(blocks):
    for k,v in b.items():
        if isinstance(v,str) and '@' in v:
            after = token_pat.sub(lambda m: vars_map.get(m.group(1), m.group(0)), v)
            if '@' in after:
                remaining.append((i,k,after))
print('Remaining tokens in-memory:', len(remaining))
for r in remaining[:40]:
    print(r)
