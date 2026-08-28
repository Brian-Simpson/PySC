from pathlib import Path
path = Path(r'C:\PySC\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit')
text = path.read_text(encoding='utf-8', errors='ignore')
lines = text.splitlines()
for idx, line in enumerate(lines, 1):
    if '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b' in line or \
       '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' in line or \
       '1.0262 - MSWRK - d3e037e1-3eb8-44c8-a917-57927947596d' in line:
        print('desc', idx, repr(line))
        for j in range(idx-5, idx+9):
            if 1 <= j <= len(lines):
                print(f'{j:4d}: {repr(lines[j-1])}')
        print('---')
