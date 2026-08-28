"""Maturity workflow tests, including the full loop:
pass-rate export -> comment-out -> recoverable coverage in gap analysis."""

from pathlib import Path

import pytest
from openpyxl import Workbook

REPO_ROOT = Path(__file__).resolve().parent.parent

from pysc.gap.extract import extract_active_checks, extract_inactive_checks  # noqa: E402
from pysc.maturity import (  # noqa: E402
    MaturityError,
    apply_proposals,
    load_pass_rates,
    propose,
)
from pysc.maturity.engine import _normalize_rate  # noqa: E402

AUDIT = '''<check_type:"Windows" version:"2">
<custom_item>
  type        : AUDIT_POWERSHELL
  description : "1.0001 - TEST - Healthy check"
  reference   : "NIST 800-53r5|AC-2"
</custom_item>
<custom_item>
  type        : AUDIT_POWERSHELL
  description : "1.0002 - TEST - Failing check"
  reference   : "NIST 800-53r5|IA-5"
</custom_item>
#<custom_item>
#  type        : AUDIT_POWERSHELL
#  description : "1.0003 - TEST - Already commented"
#  reference   : "NIST 800-53r5|SC-7"
#</custom_item>
</check_type>
'''


def _export(tmp_path, rows):
    wb = Workbook()
    ws = wb.active
    ws.append(["Description", "Pass"])
    for row in rows:
        ws.append(row)
    path = tmp_path / "export.xlsx"
    wb.save(path)
    return path


def test_normalize_rate_formats():
    assert _normalize_rate(0.85) == 0.85
    assert _normalize_rate(85) == 0.85
    assert _normalize_rate("85%") == 0.85
    assert _normalize_rate("0.85") == 0.85
    assert _normalize_rate(None) is None
    assert _normalize_rate("") is None


def test_load_pass_rates_and_missing_columns(tmp_path):
    path = _export(tmp_path, [["1.0001 - TEST - Healthy check", 0.97]])
    rates = load_pass_rates(path)
    assert rates == {"1.0001 - TEST - Healthy check": 0.97}

    wb = Workbook()
    wb.active.append(["Wrong", "Headers"])
    bad = tmp_path / "bad.xlsx"
    wb.save(bad)
    with pytest.raises(MaturityError):
        load_pass_rates(bad)


def test_maturity_loop_to_recoverable_coverage(tmp_path):
    audit = tmp_path / "HTH_TEST_BASELINE.audit"
    audit.write_text(AUDIT, encoding="utf-8")
    export = _export(
        tmp_path,
        [
            ["1.0001 - TEST - Healthy check", 97],       # above threshold
            ["1.0002 - TEST - Failing check", 62],       # below -> comment out
            ["1.0009 - TEST - Not in audit", 10],        # unmatched
        ],
    )

    proposals, unmatched = propose(audit, load_pass_rates(export), threshold=0.90)
    assert [p["description"] for p in proposals] == ["1.0002 - TEST - Failing check"]
    assert unmatched == ["1.0009 - TEST - Not in audit"]

    matured = apply_proposals(audit, proposals, tmp_path / "matured.audit")

    active = extract_active_checks(str(matured))
    inactive = extract_inactive_checks(str(matured))
    active_ids = {c["control_number"] for c in active}
    inactive_ids = {c["control_number"] for c in inactive}

    assert "1.0001" in active_ids          # healthy stays active
    assert "1.0002" not in active_ids      # failing commented out
    assert "1.0002" in inactive_ids        # ...and recoverable
    assert "1.0003" in inactive_ids        # previously commented untouched
    # The commented check's NIST ref is preserved for recoverable coverage.
    ia5 = [c for c in inactive if c["control_number"] == "1.0002"]
    assert ia5 and "IA-5" in ia5[0]["controls"]
