# Known intentional divergences from the legacy engine

## Normalization (pysc/normalize/_core.py vs pysc/_legacy/all_audits.py)

- **NetF5 keeps 3-sentence info summaries** (approved plan ruling, replacing
  the retired Normalize_f5.py's separate semantics). The engine default is
  unchanged — 1 sentence, byte-identical to legacy, enforced by the golden
  suite — but the `pysc normalize` CLI applies `[platforms.NetF5]
  info_sentences = 3` from pysc.toml, so F5 outputs produced via the CLI
  differ from the golden snapshot **in info lines only**
  (tests/test_f5_override.py codifies exactly that).

Otherwise byte-identical on every golden input.

## Platform gap analysis (pysc/gap vs NIST_audit_Gap_Analysis.py)

Extraction, rollup, and the derived analytical sets are parity-tested
(tests/test_gap_engine.py). One export-level divergence, verified on
Gap\MSSRV (workbook NIST_Audit_Batch_Comparison_processed_2608211214.xlsx):

- **"Controls Not In Baseline" includes enhancement rollups; legacy's sheet
  did not.** Candidates reference AU-9 only via AU-9(3)/AU-9(4). The legacy
  engine's analytical sets rolled these up to AU-9 (analyze_single_file), but
  its export sheet was built from raw references and dropped AU-9. The new
  exporter uses the same rolled-up sets everywhere, so AU-9 appears (16
  controls vs legacy's 15). This fixes an internal inconsistency, not a
  behavior we want to preserve.

All other reconciled numbers match: current coverage 18/1196 (1.51%),
highest potential 48, coverage opportunities 30, inactive-opportunity rows 27.

## Harvest (pysc/gap/harvest.py vs "Gap Controls.py")

None. Byte-identical output on identical inputs (174 blocks, CIS Win11
candidates + 175-control list), with the baseline-suppression path now
config-driven instead of hardcoded to MSWRK_Baseline.audit.

---

Any future intentional divergence must be recorded here (what changed, why,
which golden files are affected) AND codified in the test suite.
No undocumented diff may pass the suite.
