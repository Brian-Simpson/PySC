"""Golden-file parity tests for the normalization engine.

Rule: every engine behind `pysc normalize` must reproduce
tests/golden/legacy_snapshot/outputs/* byte-for-byte from .../inputs/* with
RUN_TIMESTAMP pinned to the snapshot value. Docker validation is stubbed out
(it mutates nothing on the happy path and requires a running daemon).

Parametrized over both engines:
- legacy: vendored monolith (pysc/_legacy/all_audits.py), the parity oracle
- core:   extracted engine (pysc/normalize/_core.py)

Intentional divergences must be documented in tests/golden/KNOWN_DIFFS.md and
codified here.
"""

import shutil
from pathlib import Path

import pytest

from pysc.config import load_config, load_legacy

GOLDEN = Path(__file__).resolve().parent / "golden" / "legacy_snapshot"
SNAPSHOT_TIMESTAMP = "26082810"  # see tests/golden/legacy_snapshot/README.md

INPUT_FILES = sorted(p.name for p in (GOLDEN / "inputs").glob("*.audit"))


def _load_engine(name):
    if name == "legacy":
        cfg = load_config(Path(__file__).resolve().parent.parent / "pysc.toml")
        return load_legacy(cfg)
    from pysc.normalize import _core

    return _core


@pytest.fixture(scope="module", params=["legacy", "core"])
def engine(request):
    module = _load_engine(request.param)
    original_timestamp = module.RUN_TIMESTAMP
    original_docker = module._run_check_audit_in_docker
    module.RUN_TIMESTAMP = SNAPSHOT_TIMESTAMP
    module._run_check_audit_in_docker = lambda audit_path: (
        127,
        "docker validation stubbed in tests",
    )
    yield module
    module.RUN_TIMESTAMP = original_timestamp
    module._run_check_audit_in_docker = original_docker


@pytest.mark.parametrize("input_name", INPUT_FILES)
def test_normalize_matches_golden(engine, tmp_path, input_name):
    work = tmp_path / "work"
    work.mkdir()
    shutil.copy2(GOLDEN / "inputs" / input_name, work / input_name)

    ok = engine.process_file(str(work / input_name))
    assert ok is not False, f"process_file reported failure for {input_name}"

    stem = Path(input_name).stem
    expected = GOLDEN / "outputs" / f"{stem}_{SNAPSHOT_TIMESTAMP}.audit"
    produced = work / "Normalized" / f"{stem}_{SNAPSHOT_TIMESTAMP}.audit"

    assert produced.is_file(), f"missing output {produced}"
    assert expected.is_file(), f"missing golden {expected}"

    produced_bytes = produced.read_bytes()
    expected_bytes = expected.read_bytes()
    assert produced_bytes == expected_bytes, (
        f"{input_name}: normalized output diverges from golden snapshot "
        f"({len(produced_bytes)} vs {len(expected_bytes)} bytes). "
        "If intentional, document in tests/golden/KNOWN_DIFFS.md."
    )


def test_snapshot_is_complete():
    assert len(INPUT_FILES) == 8
    outputs = sorted(p.name for p in (GOLDEN / "outputs").glob("*.audit"))
    assert len(outputs) == 8


def test_public_surface_importable():
    import pysc.nist
    import pysc.parser
    import pysc.normalize

    assert callable(pysc.normalize.process_file)
    assert callable(pysc.parser.parse_document)
    assert callable(pysc.nist.normalize_reference)
