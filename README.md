# PySC — HTH Tenable Audit File Management

Tooling for managing HTH's Tenable `.audit` baselines: normalizing vendor
CIS/DISA benchmark audits into the internal HTH baseline format, running
NIST SP 800-53 rev5 gap analysis, maturing baselines from fleet pass rates,
and producing enterprise compliance reporting.

> **Scope:** this repo manages the audit *files*. Ongoing audit scanning runs
> in the Tenable console; scan results come back into this tooling as Excel
> exports.

## Status

Under active modernization (see the phased plan). Current legacy entry points:

| Script | Purpose |
|---|---|
| `ALL_AUDITS.py` | Canonical engine: normalize → catalog → merge → validate → gap analysis. No-arg run processes `actual_audit_inputs\` then `audit_inputs\`. |
| `NIST_audit_Gap_Analysis.py` | Interactive OSCAL-catalog gap analysis over `Gap\<PLATFORM>\` folders. |
| `Gap Controls.py` | Harvests gap-closing checks from CIS audits per a `controls.txt` list. |
| `Normalize_f5.py` | F5-specific normalizer (being folded into the main engine). |
| `compare_f5_baseline_vs_cis.py` | F5 baseline vs CIS structural diff. |

`Normalize_AUDITS.py` is superseded by `ALL_AUDITS.py` and will be archived.

## Data layout

- `actual_audit_inputs\` — production HTH baselines (canonical)
- `audit_inputs\` — vendor CIS/DISA source benchmarks (canonical)
- `NIST_SP-800-53_rev5_catalog.json` — NIST OSCAL catalog (static reference)
- `Gap\`, `Audits\`, `Normal\`, `Normalization\` — legacy trees, being consolidated

## Setup

```powershell
& "C:\Program Files\Python39\python.exe" -m pip install -r requirements.txt
```

See `SECURITY_NOTE.md` for credential-handling rules.
