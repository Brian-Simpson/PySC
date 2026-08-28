from pathlib import Path

p = Path(r"C:\PySC\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit.bak-before-restore")
print('exists', p.exists())
if not p.exists():
    raise SystemExit('backup file missing')
text = p.read_text(encoding='utf-8', errors='ignore')
print('lines', len(text.splitlines()))
for tag in [
    '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b',
    '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    '1.0262 - MSWRK - d3e037e1-3eb8-44c8-a917-57927947596d',
]:
    print(tag, tag in text)
