"""pysc.normalize — the HTH audit normalization engine.

The implementation lives in _core.py (extracted verbatim from the legacy
engine and golden-tested against it). This package exposes the supported
surface; prefer these names over reaching into _core.
"""

from pysc.normalize._core import (  # noqa: F401
    CUSTOM_ITEM_FIELD_ORDER,
    SEE_ALSO_REPLACEMENT,
    emit,
    process_file,
    process_folder as _process_folder,
)
from pysc.normalize import _core
from pysc.normalize.manifest import load_manifest, save_manifest, should_skip_file, mark_file_processed


def run_timestamp():
    """Current output-filename timestamp (format %y%m%d%H)."""
    return _core.RUN_TIMESTAMP


def pin_run_timestamp(value):
    """Pin the output-filename timestamp (tests / reproducible runs)."""
    _core.RUN_TIMESTAMP = value


def write_parsing_results(folder):
    """Write the Parsing Results workbook for a processed folder."""
    return _core._write_parsing_results_for_folder(folder)


def reset_validation_summary():
    return _core._reset_validation_summary()


def print_validation_summary():
    return _core._print_validation_summary()


def process_folder(folder, cfg=None, open_in_vscode=False, strict_mode=False, skip_unchanged=True):
    """Process folder with optional manifest-based deduplication for CIS files.

    If cfg is provided and skip_unchanged is True, skips processing CIS files that
    haven't changed since last run.
    """
    import os

    audit_files = sorted(
        f for f in os.listdir(folder)
        if f.lower().endswith(".audit")
    )

    if not audit_files:
        print("No .audit files found.")
        return True

    manifest = None
    skipped_count = 0

    if cfg and skip_unchanged:
        manifest = load_manifest(cfg)

    print(f"\nFound {len(audit_files)} audit files.\n")

    failed_files = []

    for fname in audit_files:
        infile = os.path.join(folder, fname)

        # Check if file should be skipped
        if manifest is not None and should_skip_file(infile, manifest):
            print("-" * 60)
            print(f"Skipping (unchanged): {fname}")
            skipped_count += 1
            continue

        print("-" * 60)
        print(f"Processing: {fname}")

        ok = process_file(infile, open_in_vscode=open_in_vscode, strict_mode=strict_mode)
        if not ok:
            failed_files.append(infile)
        elif manifest is not None:
            # Mark file as processed
            mark_file_processed(infile, manifest)

    # Save manifest if we used it
    if manifest is not None:
        save_manifest(cfg, manifest)

    if skipped_count > 0:
        print(f"\nSkipped (unchanged): {skipped_count} file(s)")

    if failed_files:
        print("\nPreflight/normalization failures:")
        for path in failed_files:
            print(f"  {path}")
        if strict_mode:
            print("\nERROR: strict mode enabled and one or more files failed preflight/normalization.")
            return False

    return True


# pysc.toml platform codes -> the engine's filename-detection codes
_CONFIG_TO_DETECTION = {
    "VMware": "VMware",
    "MSSRV": "MSSRV",
    "MSWRK": "MSWRK",
    "RHEL": "RHEL",
    "MSSQL": "SQL",
    "SQL": "SQL",
    "NetIOS": "IOS",
    "NetPAFW": "PAFW",
    "NetNXOS": "NX-OS",
    "NetF5": "F5",
    "Azure": "MSAZ",
    "NetASA": "ASA",
    "AWS": "Amazon",
}


def apply_platform_overrides(cfg):
    """Load per-platform normalize overrides (e.g. NetF5 info_sentences = 3)
    from pysc.toml into the engine. Intentional divergence from the legacy
    engine's fixed 1-sentence info — see tests/golden/KNOWN_DIFFS.md."""
    overrides = {}
    for code, profile in cfg.platforms().items():
        sentences = profile.get("info_sentences")
        detection = _CONFIG_TO_DETECTION.get(code)
        if sentences and detection:
            overrides[detection] = int(sentences)
    _core.INFO_SENTENCES_BY_PLATFORM = overrides
    return overrides
