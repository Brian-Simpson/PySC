from pathlib import Path

path = Path(r'C:\PySC\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit')
text = path.read_text(encoding='utf-8', errors='ignore')
lines = text.splitlines()
markers = [
    '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b',
    '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    '1.0262 - MSWRK - d3e037e1-3eb8-44c8-a917-57927947596d'
]

for marker in markers:
    print('===', marker)
    for idx, line in enumerate(lines, 1):
        if marker in line:
            start = max(1, idx - 8)
            end = min(len(lines), idx + 8)
            for j in range(start, end + 1):
                print(f'{j:4d}: {lines[j-1]}')
            print()
            break
