import re
from pathlib import Path

path = Path(r'C:\PySC\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit')
text = path.read_text(encoding='utf-8', errors='ignore')

# Fix any info line where reference was accidentally appended on the same line.
pattern = re.compile(r'^(?P<info>\s*info\s*:\s*"[^"]*")\s+reference\s*:\s*"(?P<ref>[^"]*)"', flags=re.MULTILINE)
text_fixed, count = pattern.subn(r'\g<info>\n          reference         : "\g<ref>"', text)

# Normalize reference line indentation for consistency.
text_fixed = re.sub(r'^[ \t]*reference\s*:\s*"', '          reference         : "', text_fixed, flags=re.MULTILINE)

# Ensure see_also follows reference if reference exists and see_also exists.
# This only fixes simple ordering errors where see_also appears before reference.
pattern_order = re.compile(
    r'(?P<info>^\s*info\s*:\s*"[^"]*"\s*$\n)(?P<see>^\s*see_also\s*:\s*"[^"]*"\s*$\n)(?P<ref>^\s*reference\s*:\s*"[^"]*"\s*$\n)',
    flags=re.MULTILINE,
)
text_fixed = pattern_order.sub(r'\g<info>\g<ref>\g<see>', text_fixed)

# Write out only if changes were made.
if text_fixed != text:
    backup = path.with_suffix(path.suffix + '.bak-after-fix2')
    path.write_text(text_fixed, encoding='utf-8')
    backup.write_text(text, encoding='utf-8')
    print(f'patched {count} broken info/reference lines')
    print(f'backup written to {backup}')
else:
    print('no changes needed')

# verify no same-line issues remain
remaining = re.findall(r'^\s*info\s*:\s*"[^"]*"\s+reference\s*:\s*"', text_fixed, flags=re.MULTILINE)
print('remaining broken lines', len(remaining))
