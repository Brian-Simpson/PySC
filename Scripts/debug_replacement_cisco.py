import sys
from pathlib import Path
sys.path.insert(0, r"C:\PySC")
import audit_custom_items_to_excel as a
p = Path(r"C:\PySC\Audits\CIS_Cisco_IOS_12_v4.0.0_Level_1.audit")
text = p.read_text(encoding='utf-8', errors='replace')
vars_map = a.parse_variables(text)
blocks = a.parse_custom_items(text)
print('vars_map sample:', list(vars_map.items())[:10])
count = 0
import re
for b in blocks:
    for k,v in b.items():
        if isinstance(v,str) and '@' in v:
            before = v
            token_pat = re.compile(r'@([A-Za-z0-9_]+)@')
            def _repl(m):
                var = m.group(1)
                return vars_map.get(var, m.group(0))
            after = token_pat.sub(_repl, v)
            if before != after:
                print('Replaced in block desc:', b.get('description','(no desc)') )
                print(' key:',k)
                print(' before:', before)
                print(' after:', after)
                count += 1
            else:
                print('NOT replaced for:', k, before)
                count += 1
    if count>40:
        break
print('done')
