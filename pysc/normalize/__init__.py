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
