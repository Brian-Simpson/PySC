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
    process_folder,
)
from pysc.normalize import _core


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
