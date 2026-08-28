from pathlib import Path
path = Path(r'C:\PySC\Normalization\MSWRK\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit')
text = path.read_text(encoding='utf-8', errors='ignore')
lines = text.splitlines()
for i, line in enumerate(lines, 1):
    if '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' in line:
        for j in range(max(1, i-8), min(len(lines), i+8)+1):
            print(f'{j:5d}: {lines[j-1]}')
        break
