# Golden snapshot — legacy ALL_AUDITS.py output

Provenance: produced 2026-08-28 by running the repo-root `ALL_AUDITS.py`
(commit 36e324b, byte-identical to `pysc/_legacy/all_audits.py`) against the
8 files in `inputs\`:

```
& "C:\Program Files\Python39\python.exe" C:\PySC\ALL_AUDITS.py <inputs-copy-dir>
```

- `RUN_TIMESTAMP` for this run: **26082810** (format `%y%m%d%H`; embedded in
  output filenames).
- All 8 files passed Docker `tenable/audit-utils` check_audit validation
  (Passed: 8, Failed: 0, Skipped: 0).
- The controls-catalog workbook step errored on this run (openpyxl was not
  yet installed), so this snapshot covers the normalized `.audit` outputs
  only. Catalog goldens are captured separately once needed by Phase 2.

Representative coverage: production baselines (MSSRV, MSWRK, RHEL, NetF5)
plus vendor CIS sources (Windows Server 2022 L1 MS, Windows 11 Enterprise
L1, RHEL 10 L1 Server, F5 L1).

Parity rule (Phase 2): the extracted `pysc.normalize` engine must reproduce
`outputs\*` byte-for-byte from `inputs\*` with `RUN_TIMESTAMP` pinned to
26082810. Any intentional divergence must be recorded in
`tests\golden\KNOWN_DIFFS.md` with a codifying test.
