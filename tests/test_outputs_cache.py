"""Validation cache + output organizer tests."""

import types
from pathlib import Path

from pysc.config import Config
from pysc.outputs import archive_previous_output, organize_outputs
from pysc.validation_cache import ValidationCache


def _fake_cfg(root):
    data = {
        "paths": {
            "production_inputs": "actual_audit_inputs",
            "vendor_inputs": "audit_inputs",
            "report_output": "Output",
        }
    }
    return Config(data, root / "pysc.toml")


def test_validation_cache_skips_unchanged_content(tmp_path):
    calls = []

    def real_check(audit_path):
        calls.append(audit_path)
        return (0, "docker ok") if "good" in Path(audit_path).name else (1, "docker fail")

    module = types.SimpleNamespace(_run_check_audit_in_docker=real_check)
    cache = ValidationCache(tmp_path / "validation_cache.json")
    cache.wrap(module)

    good = tmp_path / "good.audit"
    good.write_text("content-v1", encoding="utf-8")

    # First run: real Docker. Second run, same bytes: cached.
    assert module._run_check_audit_in_docker(str(good))[0] == 0
    code, msg = module._run_check_audit_in_docker(str(good))
    assert code == 0 and "cached" in msg
    assert len(calls) == 1 and cache.hits == 1

    # Changed bytes: cache miss, real validation again.
    good.write_text("content-v2", encoding="utf-8")
    assert module._run_check_audit_in_docker(str(good))[0] == 0
    assert len(calls) == 2

    # Failures are never cached.
    bad = tmp_path / "bad.audit"
    bad.write_text("broken", encoding="utf-8")
    assert module._run_check_audit_in_docker(str(bad))[0] == 1
    assert module._run_check_audit_in_docker(str(bad))[0] == 1
    assert len(calls) == 4

    # Cache persists: a new instance still skips the good file.
    module2 = types.SimpleNamespace(_run_check_audit_in_docker=real_check)
    cache2 = ValidationCache(tmp_path / "validation_cache.json")
    cache2.wrap(module2)
    code, msg = module2._run_check_audit_in_docker(str(good))
    assert code == 0 and "cached" in msg
    # Double-wrap is a no-op.
    cache2.wrap(module2)
    assert getattr(module2._run_check_audit_in_docker, "_pysc_cached", False)


def test_organize_outputs_routes_artifacts(tmp_path):
    cfg = _fake_cfg(tmp_path)
    prod = tmp_path / "actual_audit_inputs"
    vendor = tmp_path / "audit_inputs"
    (prod / "Normalized").mkdir(parents=True)
    (prod / "Merged").mkdir()
    vendor.mkdir()
    output = tmp_path / "Output"
    output.mkdir()

    (prod / "Parsing Results_2609011200.xlsx").write_text("x")
    (prod / "Production_NIST_Reference_Gap_Analysis_2609.xlsx").write_text("x")
    (prod / "Normalized" / "Unique_Controls_Catalog_2609.xlsx").write_text("x")
    (prod / "Normalized" / "HTH_MSSRV_BASELINE_2609.audit").write_text("stays")
    (prod / "Merged" / "Merged_MSSRV_2609.audit").write_text("x")
    (vendor / "Parsing Results_2609011201.xlsx").write_text("x")
    (output / "Unified_Compliance_Matrix_2609.xlsx").write_text("x")
    (output / "dashboard_2609.html").write_text("x")

    moved = organize_outputs(cfg, progress=lambda *_: None)
    assert len(moved) == 8

    processed = output / "Processed"
    reports = output / "Reports"
    assert (processed / "Parsing Results_2609011200.xlsx").is_file()
    assert (processed / "Parsing Results_2609011201.xlsx").is_file()
    assert (processed / "Production_NIST_Reference_Gap_Analysis_2609.xlsx").is_file()
    # Whole Normalized/ and Merged/ trees relocate under Processed, structure kept.
    assert (processed / "Normalized" / "Unique_Controls_Catalog_2609.xlsx").is_file()
    assert (processed / "Normalized" / "HTH_MSSRV_BASELINE_2609.audit").is_file()
    assert (processed / "Merged" / "Merged_MSSRV_2609.audit").is_file()
    assert (reports / "Unified_Compliance_Matrix_2609.xlsx").is_file()
    assert (reports / "dashboard_2609.html").is_file()
    # Normalized .audit is now swept out of the input tree.
    assert not (prod / "Normalized" / "HTH_MSSRV_BASELINE_2609.audit").exists()
    # A manifest inventorying Output\Processed is written.
    manifest = processed / "manifest.csv"
    assert manifest.is_file()
    text = manifest.read_text(encoding="utf-8")
    assert "relative_path,category,size_bytes,modified" in text
    assert "Normalized/HTH_MSSRV_BASELINE_2609.audit" in text


def test_archive_previous_output_moves_whole_tree(tmp_path):
    data = {
        "paths": {
            "report_output": "Output",
            "output_archive": str(tmp_path / "TAPARCHIVE"),
        }
    }
    cfg = Config(data, tmp_path / "pysc.toml")
    output = tmp_path / "Output"
    (output / "Reports").mkdir(parents=True)
    (output / "Reports" / "dashboard_2609.html").write_text("x")
    (output / "Processed").mkdir()
    (output / "Processed" / "manifest.csv").write_text("x")

    destination = archive_previous_output(cfg, progress=lambda *_: None)

    assert destination is not None
    assert destination.parent == tmp_path / "TAPARCHIVE"
    assert (destination / "Reports" / "dashboard_2609.html").is_file()
    assert (destination / "Processed" / "manifest.csv").is_file()
    # Output\ is gone; a fresh run's mkdir(parents=True) recreates it clean.
    assert not output.exists()


def test_archive_previous_output_noop_when_unconfigured(tmp_path):
    data = {"paths": {"report_output": "Output"}}
    cfg = Config(data, tmp_path / "pysc.toml")
    output = tmp_path / "Output"
    output.mkdir()
    (output / "keep.txt").write_text("x")

    assert archive_previous_output(cfg, progress=lambda *_: None) is None
    assert (output / "keep.txt").is_file()


def test_archive_previous_output_noop_when_output_empty(tmp_path):
    data = {
        "paths": {
            "report_output": "Output",
            "output_archive": str(tmp_path / "TAPARCHIVE"),
        }
    }
    cfg = Config(data, tmp_path / "pysc.toml")
    (tmp_path / "Output").mkdir()

    assert archive_previous_output(cfg, progress=lambda *_: None) is None
    assert not (tmp_path / "TAPARCHIVE").exists()

