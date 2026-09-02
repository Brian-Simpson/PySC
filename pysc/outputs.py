"""Output organization: route artifacts into Output\\Reports and Output\\Processed.

The verbatim legacy engine writes its working artifacts inside the input
trees (Parsing Results at the tree root, catalogs/crosswalk in Normalized\\,
merged audits in Merged\\). Rather than modify the parity-gated engine, the
pipeline commands call organize_outputs() afterwards to sweep those artifact
classes into Output\\Processed. Report deliverables are written directly to
Output\\Reports by their producers.

The full Normalized\\, For_Gap\\, and Merged\\ working trees (every file, with
their internal directory structure preserved) are relocated under
Output\\Processed so a run's complete intermediate state lives in one place, and
a manifest.csv inventorying Output\\Processed is written alongside them. Each run
regenerates the trees from the inputs, so moving them post-run is non-destructive.

archive_previous_output() runs before a fresh refresh/run pipeline starts: it
relocates the entire previous Output\\ tree (Reports + Processed from the last
run) into a timestamped folder under the configured output_archive root, so
every run's deliverables are preserved rather than overwritten in place.
"""

import csv
import shutil
import time
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

# Working trees swept whole (internal structure preserved) into Output\Processed.
PROCESSED_TREES = ("Normalized", "For_Gap", "Merged")

MANIFEST_NAME = "manifest.csv"


def archive_previous_output(cfg, progress=print):
    """Move the entire previous Output\\ tree into a timestamped folder under
    the configured output_archive root, before a fresh run regenerates Output.
    No-op when output_archive is unset or Output\\ doesn't exist/is empty."""
    archive_root = cfg.path("output_archive")
    if archive_root is None:
        return None
    source = cfg.path("report_output")
    if source is None or not source.is_dir():
        return None
    if not any(source.iterdir()):
        return None  # nothing to archive yet

    stamp = time.strftime("%Y%m%d_%H%M%S")
    destination = Path(archive_root) / f"Output_{stamp}"
    try:
        archive_root_path = Path(archive_root)
        archive_root_path.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
    except OSError as exc:
        progress(f"Could not archive previous Output\\ to {destination}: {exc}")
        return None
    progress(f"Archived previous Output\\ -> {destination}")
    return destination


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


def _move_tree(source, destination, moved):
    """Move every file under source into destination, preserving the relative
    directory structure. Skips a no-op move when source resolves to destination."""
    source = Path(source)
    if not source.is_dir():
        return
    if source.resolve() == Path(destination).resolve():
        return
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        target = Path(destination) / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if target.exists():
                target.unlink()
            shutil.move(str(path), str(target))
            moved.append(target)
        except (PermissionError, OSError):
            pass  # locked file - swept on a later run


def _write_manifest(out_processed):
    """Inventory Output\\Processed into manifest.csv (relative path, category,
    size, modified). Overwritten each run to reflect current contents."""
    manifest = out_processed / MANIFEST_NAME
    rows = []
    for path in sorted(out_processed.rglob("*")):
        if not path.is_file() or path.name == MANIFEST_NAME:
            continue
        rel = path.relative_to(out_processed)
        category = rel.parts[0] if len(rel.parts) > 1 else "root"
        try:
            stat = path.stat()
            size = stat.st_size
            modified = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
        except OSError:
            size, modified = "", ""
        rows.append((rel.as_posix(), category, size, modified))
    try:
        with open(manifest, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["relative_path", "category", "size_bytes", "modified"])
            writer.writerows(rows)
    except OSError:
        return None
    return manifest


def organize_outputs(cfg, progress=print):
    """Sweep working artifacts into Output\\Processed and stray deliverables
    (e.g. locked-workbook fallbacks) into Output\\Reports, then write a manifest
    of Output\\Processed."""
    moved = []
    out_reports = reports_dir(cfg)
    out_processed = processed_dir(cfg)

    for root_key in ("production_inputs", "vendor_inputs"):
        root = cfg.path(root_key)
        if root is None:
            continue
        _move_all(PROCESSED_ROOT_PATTERNS, root, out_processed, moved)
        for tree in PROCESSED_TREES:
            _move_tree(root / tree, out_processed / tree, moved)

    # Staged gap inputs may be config-redirected outside the input trees.
    gap_staging = cfg.path("gap_staging")
    if gap_staging is not None:
        _move_tree(gap_staging, out_processed / "For_Gap", moved)

    # Deliverables written to the Output root (older runs, fallbacks).
    _move_all(REPORT_PATTERNS, cfg.path("report_output"), out_reports, moved)

    manifest = _write_manifest(out_processed)

    if moved or manifest:
        progress(
            f"Organized {len(moved)} artifact(s) -> "
            f"{out_reports.name}\\ and {out_processed.name}\\ "
            f"(manifest: {out_processed.name}\\{MANIFEST_NAME})"
        )
    return moved
