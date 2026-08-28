"""Phase 4 tests: enterprise driver, history store, matrix + dashboard builds."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "NIST_SP-800-53_rev5_catalog.json"

from pysc.gap.engine import analyze_files  # noqa: E402
from pysc.gap.enterprise import DETECTION_TO_PLATFORM, EnterpriseGapResult  # noqa: E402
from pysc.history import HistoryStore  # noqa: E402
from pysc.report.excel_util import sanitize_for_excel  # noqa: E402
from pysc.report.html import build_dashboard  # noqa: E402
from pysc.report.matrix import build_matrix  # noqa: E402

BASELINE_AUDIT = '''<check_type:"Windows" version:"2">
<custom_item>
  type        : AUDIT_POWERSHELL
  description : "1.0001 - TEST - Active check"
  reference   : "NIST 800-53r5|AC-2"
</custom_item>
#<custom_item>
#  type        : AUDIT_POWERSHELL
#  description : "1.0002 - TEST - Commented check"
#  reference   : "NIST 800-53r5|IA-5"
#</custom_item>
</check_type>
'''

CANDIDATE_AUDIT = '''<check_type:"Windows" version:"2">
<custom_item>
  type        : AUDIT_POWERSHELL
  description : "2.1 Candidate covers IA-5"
  reference   : "NIST 800-53r5|IA-5"
</custom_item>
<custom_item>
  type        : AUDIT_POWERSHELL
  description : "2.2 Candidate covers SC-7"
  reference   : "NIST 800-53r5|SC-7"
</custom_item>
</check_type>
'''


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    root = tmp_path_factory.mktemp("enterprise")
    baseline = root / "HTH_TEST_BASELINE.audit"
    candidate = root / "CIS_Candidate.audit"
    baseline.write_text(BASELINE_AUDIT, encoding="utf-8")
    candidate.write_text(CANDIDATE_AUDIT, encoding="utf-8")
    analysis = analyze_files(baseline, [candidate], CATALOG)
    return EnterpriseGapResult(
        {"MSSRV": analysis},
        {"NetACI": ["CIS_ACI_candidate.audit"]},
        ["weird_file.audit"],
    )


def test_detection_mapping_covers_all_configured_platforms():
    from pysc.config import load_config

    cfg = load_config(REPO_ROOT / "pysc.toml")
    mapped = set(DETECTION_TO_PLATFORM.values())
    configured = set(cfg.platforms())
    # Every mapped code must exist in config; NetACI has no filename detection.
    assert mapped <= configured
    assert configured - mapped == {"NetACI"}


def test_history_roundtrip(result, tmp_path):
    store = HistoryStore(tmp_path / "hist.sqlite")
    run1 = store.record_enterprise_run(result, notes="t1")
    run2 = store.record_enterprise_run(result, notes="t2")
    assert run2 == run1 + 1

    rows = store.platform_trend("MSSRV")
    assert len(rows) == 2
    _run, _ts, platform, covered, recoverable, total = rows[0]
    assert platform == "MSSRV"
    assert covered >= 1          # AC-2
    assert recoverable >= 1      # IA-5 via commented check
    assert total > 1000          # full base catalog

    out = store.export_csv(tmp_path / "hist.csv")
    text = Path(out).read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("run_id,ts,platform,family")
    store.close()


def test_matrix_build(result, tmp_path):
    store = HistoryStore(tmp_path / "hist.sqlite")
    store.record_enterprise_run(result)
    out = build_matrix(result, tmp_path / "matrix.xlsx", history=store)
    store.close()

    from openpyxl import load_workbook

    wb = load_workbook(out)
    assert wb.sheetnames == [
        "Executive_Summary", "Platform_Family_Coverage", "NIST_Matrix",
        "Priority_Gaps", "Trend",
    ]
    ws = wb["Executive_Summary"]
    platforms = [ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)]
    assert "MSSRV" in platforms and "NetACI" in platforms
    trend = wb["Trend"]
    assert trend.max_row >= 2  # snapshot present


def test_dashboard_build(result, tmp_path):
    out = build_dashboard(result, tmp_path / "dash.html")
    text = Path(out).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text
    assert "MSSRV" in text
    assert "NO BASELINE" in text            # NetACI surfaced
    assert "prefers-color-scheme: dark" in text
    assert "Coverage % by platform and NIST family" in text


def test_sanitize_for_excel_formula_guard():
    assert sanitize_for_excel("=1+2") == "'=1+2"
    assert sanitize_for_excel("@cmd") == "'@cmd"
    assert sanitize_for_excel("plain") == "plain"
    assert sanitize_for_excel(None) == ""
