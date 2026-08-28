# SECURITY NOTE — Credentials requiring rotation

**Created 2026-08-28 during repo hygiene review. Action owner: IT Security.**

The following files in this workspace contain **plaintext credentials**. The
directories holding them are excluded from git via `.gitignore`, but the keys
were exposed on disk and should be **rotated** regardless:

| File | Credential |
|---|---|
| `old\PySC\Custom\Tenable_dev.py` (lines 13-14) | Tenable.SC access + secret key |
| `old\HTHITSEC\Python\pyten_working.py` (lines 33-34) | Same Tenable.SC key pair |
| `AppTest\S1_1_5k.py` (lines 4-5) | SentinelOne API JWT (expires ~2027) |
| `ApplicationInventory\VTScore.py` (line 32) and `old\PySC\VTScore.py` | VirusTotal API key |
| `ApplicationInventory\OTX.py` (line 16) and `old\PySC\OTX.py` | AlienVault OTX API key |

Rules going forward:

1. Never commit credentials. Keys belong in environment variables or the
   Windows Credential Manager, never in source.
2. Never copy code out of `old\` Tenable.SC scripts — they embed the keys.
3. `.env`, `*.pem`, and `secrets*.json` are git-ignored as a safety net.
