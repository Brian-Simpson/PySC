"""Output organization: route artifacts into Output\\Reports and Output\\Processed.

The verbatim legacy engine writes its working artifacts inside the input
trees (Parsing Results at the tree root, catalogs/crosswalk in Normalized\\,
merged audits in Merged\\). Rather than modify the parity-gated engine, the
pipeline commands call organize_outputs() afterwards to sweep those artifact
classes into Output\\Processed. Report deliverables are written directly to
Output\\Reports by their producers. Normalized .audit files stay in place -
they are pipeline state the next run consumes.
"""

import shutil
from pathlib import Path

REPORT_PATTERNS = (
    "Unified_Compliance_Matrix_*.xlsx",
    "dashboard_*.html",
    "Maturity_Proposals_*.xlsx",
    "Control_Library_*.xlsx",
)

PROCESSED_ROOT_PATTERNS = (
    "Parsing Results_*.xlsx",
    "Production_NIST_Reference_Gap_Analysis_*.xlsx",
)


def reports_dir(cfg):
    path = cfg.path("report_output") / "Reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def processed_dir(cfg):
    path = cfg.path("report_output") / "Processed"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _move_all(patterns, source, destination, moved):
    source = Path(source)
    if not source.is_dir():
        return
    destination.mkdir(parents=True, exist_ok=True)
    for pattern in patterns:
        for path in sorted(source.glob(pattern)):
            if path.is_file():
                target = destination / path.name
                try:
                    shutil.move(str(path), str(target))
                    moved.append(target)
                except (PermissionError, OSError):
                    pass  # open in Excel etc. - swept on a later run


def organize_outputs(cfg, progress=print):
    """Sweep working artifacts into Output\\Processed and stray deliverables
    (e.g. locked-workbook fallbacks) into Output\\Reports."""
    moved = []
    out_reports = reports_dir(cfg)
    out_processed = processed_dir(cfg)

    for root_key in ("production_inputs", "vendor_inputs"):
        root = cfg.path(root_key)
        if root is None:
            continue
        _move_all(PROCESSED_ROOT_PATTERNS, root, out_processed, moved)
        _move_all(("*.xlsx",), root / "Normalized", out_processed, moved)
        _move_all(("*.audit",), root / "Merged", out_processed / "Merged", moved)

    # Deliverables written to the Output root (older runs, fallbacks).
    _move_all(REPORT_PATTERNS, cfg.path("report_output"), out_reports, moved)

    if moved:
        progress(
            f"Organized {len(moved)} artifact(s) -> "
            f"{out_reports.name}\\ and {out_processed.name}\\"
        )
    return moved
