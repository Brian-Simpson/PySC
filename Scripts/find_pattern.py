from pathlib import Path
pattern = '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b'
root = Path(r'C:\PySC\Normalization\MSWRK')
for path in root.rglob('*.audit'):
    text = path.read_text(encoding='utf-8', errors='ignore')
    if pattern in text:
        print(path)
        idx = text.index(pattern)
        start = max(0, idx - 400)
        end = min(len(text), idx + 400)
        snippet = text[start:end]
        print('--- snippet ---')
        print(snippet)
        break
else:
    print('not found')
