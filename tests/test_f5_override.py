"""NetF5 info_sentences=3 override: the one intentional normalize divergence.

The CLI applies pysc.toml platform overrides; the engine default (no
overrides) remains byte-identical to the legacy engine, which the golden
parity suite enforces separately.
"""

import shutil
from pathlib import Path

import pytest

from pysc import normalize
from pysc.config import load_config
from pysc.normalize import _core

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "golden" / "legacy_snapshot"
SNAPSHOT_TIMESTAMP = "26082810"
F5_INPUT = "CIS_F5_Networks_Benchmark_v1.0.0_L1.audit"


@pytest.fixture()
def f5_engine():
    original_timestamp = _core.RUN_TIMESTAMP
    original_docker = _core._run_check_audit_in_docker
    original_overrides = _core.INFO_SENTENCES_BY_PLATFORM
    _core.RUN_TIMESTAMP = SNAPSHOT_TIMESTAMP
    _core._run_check_audit_in_docker = lambda audit_path: (127, "stubbed")
    yield
    _core.RUN_TIMESTAMP = original_timestamp
    _core._run_check_audit_in_docker = original_docker
    _core.INFO_SENTENCES_BY_PLATFORM = original_overrides


def test_config_declares_f5_override():
    cfg = load_config(REPO_ROOT / "pysc.toml")
    overrides = normalize.apply_platform_overrides(cfg)
    try:
        assert overrides == {"F5": 3}
    finally:
        _core.INFO_SENTENCES_BY_PLATFORM = {}


def test_f5_override_expands_info_only(f5_engine, tmp_path):
    cfg = load_config(REPO_ROOT / "pysc.toml")
    normalize.apply_platform_overrides(cfg)

    work = tmp_path / "work"
    work.mkdir()
    shutil.copy2(GOLDEN / "inputs" / F5_INPUT, work / F5_INPUT)
    normalize.process_file(str(work / F5_INPUT))

    stem = Path(F5_INPUT).stem
    produced = (work / "Normalized" / f"{stem}_{SNAPSHOT_TIMESTAMP}.audit").read_text(
        encoding="utf-8"
    )
    golden = (GOLDEN / "outputs" / f"{stem}_{SNAPSHOT_TIMESTAMP}.audit").read_text(
        encoding="utf-8"
    )

    produced_lines = produced.splitlines()
    golden_lines = golden.splitlines()
    assert len(produced_lines) == len(golden_lines)
    diff_lines = [
        (p, g) for p, g in zip(produced_lines, golden_lines) if p != g
    ]
    # The override must change something (richer info) and ONLY info lines.
    assert diff_lines, "override had no effect on F5 output"
    for produced_line, golden_line in diff_lines:
        assert produced_line.lstrip().startswith("info"), (
            f"non-info line diverged under F5 override: {produced_line!r}"
        )
        assert golden_line.lstrip().startswith("info")
