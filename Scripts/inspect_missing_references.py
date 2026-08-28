from pathlib import Path
import re

path = Path(r'C:\PySC\HTH_Win_11_Enterprise_v5.0.1_L1_BL_20260515_ALLIN.audit')
text = path.read_text(encoding='utf-8', errors='ignore')
blocks = re.findall(r'<custom_item>.*?</custom_item>', text, re.DOTALL)
missing = [
    'Windows 11 is installed',
    'Windows 11 installation type',
    '1.0255 - MSWRK - 3b576869-a4ec-4529-8536-b80a7769e899',
    '1.0256 - MSWRK - 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    '1.0257 - MSWRK - 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
    '1.0258 - MSWRK - 56a863a9-875e-4185-98a7-b882c64b5ce5',
    '1.0259 - MSWRK - d4f940ab-401b-4efc-aadc-ad5f3c50688a',
    '1.0260 - MSWRK - e6db77e5-3df2-4cf1-b95a-636979351e5b',
    '1.0261 - MSWRK - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    '1.0262 - MSWRK - d3e037e1-3eb8-44c8-a917-57927947596d',
    '1.0263 - MSWRK - 5beb7efe-fd9a-4556-801d-275e5ffc04cc',
    '1.0264 - MSWRK - 26190899-1602-49e8-8b27-eb1d0a1ce869',
    '1.0265 - MSWRK - b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
    '1.0266 - MSWRK - be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
    '1.0267 - MSWRK - 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
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
listed = []
for block in blocks:
    desc_match = re.search(r'description\s*:\s*"([^"]*)"', block)
    desc = desc_match.group(1).strip() if desc_match else 'NO_DESCRIPTION'
    ref_match = re.search(r'reference\s*:\s*"([^"]*)"', block)
    ref = ref_match.group(1).strip() if ref_match else None
    if any(m in desc for m in missing):
        print('---')
        print('DESCRIPTION:', desc)
        print('REFERENCE:', ref)
        for line in block.splitlines():
            print(line)
        listed.append(desc)
print('FOUND', len(listed), 'of', len(missing))
