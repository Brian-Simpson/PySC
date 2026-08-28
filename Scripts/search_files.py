from pathlib import Path
pattern = '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
root = Path(r'C:\PySC\Normalization\MSWRK')
for path in root.rglob('*.audit'):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception as exc:
        continue
    if pattern in text:
        print(path)
