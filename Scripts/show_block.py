from pathlib import Path
pattern = '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b'
path = Path(r'C:\PySC\Normalization\MSWRK\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_5.audit')
text = path.read_text(encoding='utf-8', errors='ignore')
lines = text.splitlines()
for i, line in enumerate(lines, 1):
    if pattern in line:
        for j in range(max(1, i-10), min(len(lines), i+10)+1):
            print(f'{j:5d}: {lines[j-1]}')
        break
else:
    print('not found')
