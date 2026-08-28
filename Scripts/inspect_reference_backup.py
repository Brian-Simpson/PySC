from pathlib import Path
import re

files = [
    Path(r'C:\PySC\Normalization\MSWRK\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_5.audit'),
    Path(r'C:\PySC\Normalization\MSWRK\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260506_ALLIN.audit'),
]

patterns = [
    '1.0255 - MSWRK - 3b576869-a4ec-4529-8536-b80a7769e899',
    '1.0256 - MSWRK - 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    '1.0257 - MSWRK - 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
    '1.0258 - MSWRK - 56a863a9-875e-4185-98a7-b882c64b5ce5',
    '1.0259 - MSWRK - d4f940ab-401b-4efc-aadc-ad5f3c50688a',
    '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b',
    '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    '1.0262 - MSWRK - d3e037e1-3eb8-44c8-a917-57927947596d',
    '1.0295 - MSWRK - Ensure ShellSmartScreenLevel is Windows: Registry Value to Block',
    '1.0296 - MSWRK - EnableSmartScreen',
    '1.0316 - MSWRK - Value of DeferQualityUpdatesPeriodInDays',
    '1.0317 - MSWRK - Value of DeferQualityUpdates',
    '1.0324 - MSWRK - 32-bit subsystem on 64-bit OS - Config',
    '1.0327 - MSWRK - Ensure AutoAdminLogon is Windows: Registry Value to 0',
    '1.0328 - MSWRK - Ensure DefaultPassword does not exist',
    '1.0336 - MSWRK - NETLOGON Ensure the client verifies the identity of the server using Kerberos authentication.',
    '1.0337 - MSWRK - SYSVOL Ensure the client verifies the identity of the server using Kerberos authentication.',
]

for fn in files:
    if not fn.exists():
        print('MISSING FILE', fn)
        continue
    text = fn.read_text(encoding='utf-8', errors='ignore')
    print('=== FILE', fn)
    for desc in patterns:
        idx = text.find(desc)
        if idx == -1:
            continue
        start = text.rfind('<custom_item>', 0, idx)
        end = text.find('</custom_item>', idx)
        if start == -1 or end == -1:
            continue
        block = text[start:end+len('</custom_item>')]
        ref_match = re.search(r'reference\s*:\s*"([^"]*)"', block)
        ref = ref_match.group(1) if ref_match else 'NONE'
        print('DESC:', desc)
        print('REF :', ref)
        print('---')
