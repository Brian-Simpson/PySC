from pathlib import Path
import re
root = Path(r'c:\PySC\Audits')
terms = ['F5','PaloAlto','Palo Alto','Cisco','IOS','NXOS','ASA','BIG-IP','PAN-OS','firewall']
regex = re.compile('|'.join(re.escape(t) for t in terms), re.IGNORECASE)
counts = {}
for p in sorted(root.glob('*.audit')):
    text = p.read_text(encoding='utf-8', errors='ignore')
    found = regex.findall(text)
    if found:
        counts[p.name] = set(m.lower() for m in found)
print('matches:', len(counts))
for k,v in counts.items():
    print(k, sorted(v))
