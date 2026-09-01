# PySC — HTH Tenable Audit File Management

Tooling for managing HTH's Tenable `.audit` baselines: normalizing vendor
CIS/DISA benchmark audits into the internal HTH baseline format, running
NIST SP 800-53 rev5 gap analysis, maturing baselines from fleet pass rates,
and producing enterprise compliance reporting.

> **Scope:** this repo manages the audit *files*. Ongoing audit scanning runs
> in the Tenable console; scan results come back into this tooling as Excel
> exports.

## Setup

```powershell
& "C:\Program Files\Python39\python.exe" -m pip install -r requirements.txt
```

Configuration lives in `pysc.toml` (paths, normalize defaults, one
`[platforms.<CODE>]` profile per platform declaring its production baseline).
Docker Desktop (with the `tenable/audit-utils` image) enables check_audit
validation during normalization; without it, validation is skipped.

## CLI

All commands: `python -m pysc <command>` (run from `C:\PySC`).

| Command | Purpose |
|---|---|
| `download [--apply] [--all] [--no-library]` | Fetch Tenable's `audits.tar.gz` (SHA-256 verified), stage UPDATED/NEW_VERSION benchmarks for curated families into `audit_inputs\_incoming_<ts>\`; `--apply` copies them in, reports each file's NEW/KNOWN controls against the library, and rebuilds it |
| `normalize <file\|folder> [--strict] [--engine legacy]` | Normalize vendor audits into HTH baseline format (golden-tested engine; catalog + merge follow automatically on folder runs) |
| `run` | Full legacy-equivalent pipeline: production + vendor inputs, catalogs, crosswalk, merge, production gap analysis |
| `gap platform --dir <folder> [--platform CODE]` | Baseline vs candidates for one platform against the OSCAL catalog, incl. recoverable coverage from commented-out checks |
| `gap production [--stage]` | Whole-estate reference gap analysis (legacy engine) |
| `gap harvest --dir <folder> [--platform CODE]` | Pull gap-closing checks from candidate audits into a paste-ready `.audit` |
| `gap f5-compare --dir <folder> [--splice-orphans]` | F5 structural diff by (f5_command, json_transform) signature |
| `library build [--include-normalized]` | Rebuild the registry: `control_library.json` + the single master `Control_Library.xlsx` (repo root, overwritten each build; falls back to a timestamped copy in `Output\` if the master is open in Excel). Every control keyed by what-is-audited; expectations recorded, variance + duplicates flagged |
| `library check <audit> [--verbose]` | Classify an audit's checks against the library: NEW / KNOWN / EXPECTATION_DIFFERS / DUPLICATE_IN_FILE |
| `report matrix\|html\|all` | Unified_Compliance_Matrix workbook and/or self-contained HTML dashboard into `Output\`; records a history snapshot |
| `history show\|export` | Per-run per-platform coverage trend from `pysc_history.sqlite` |
| `maturity --audit <baseline> --pass-rates <export.xlsx> [--apply]` | Propose/apply comment-outs for checks under the fleet pass-rate threshold (default 90%) |
| `catalog`, `match-catalogs`, `validate`, `threat-intel` | Catalog/crosswalk/Docker-validation utilities |

## The maturity loop

1. Pull current vendor benchmarks from Tenable downloads (`pysc download`,
   review the staged manifest, then `pysc download --apply`).
2. Normalize vendor benchmarks; merge into the HTH baseline (`pysc run`).
3. Load the baseline into the Tenable console and scan.
4. Export scan results to Excel (Description + Pass columns).
5. `pysc maturity --audit <baseline> --pass-rates <export> --apply` comments
   out checks failing fleet-wide.
6. Commented checks surface as **recoverable coverage** in `pysc gap` — the
   remediation queue for bringing them back.
7. `pysc report all` publishes the executive workbook + dashboard and records
   the trend snapshot.

## Data layout

- `actual_audit_inputs\` — production HTH baselines (canonical)
- `audit_inputs\` — vendor CIS/DISA source benchmarks (canonical)
- `Output\` — generated reports (git-ignored)
- `NIST_SP-800-53_rev5_catalog.json` — NIST OSCAL catalog (static reference)
- `pysc\` — the package (`pysc\_legacy\` holds the vendored parity oracle)
- `tests\golden\` — byte-parity snapshots; see `KNOWN_DIFFS.md` for the
  documented divergences (no undocumented diff passes the suite)
- `Archive\2026-08_legacy\` — superseded scripts and trees (git-ignored,
  preserved on disk; also in git history before commit d059730's follow-up)

`ALL_AUDITS.py` and `NIST_audit_Gap_Analysis.py` retired to
`Archive\2026-08_legacy\` on 2026-09-01 after two clean validated production
cycles; the vendored copy in `pysc\_legacy\` remains the byte-parity oracle
for the golden test suite.

Legacy-only inputs that never existed in this workspace and are NOT required
by the package: `Baseline_-_MSSRV.csv`, `Merged_2607.csv`,
`MSSRV_Mature.xlsx`/`MSWRK_Mature.xlsx` (replaced by `pysc maturity`
pass-rate exports).

See `SECURITY_NOTE.md` for credential-handling rules and keys pending rotation.
