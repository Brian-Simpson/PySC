"""Unified gap engine tests.

Parity: pysc.gap extraction/rollup must match the legacy interactive engine
(NIST_audit_Gap_Analysis.py) on real Gap-folder audit files. The legacy module
is imported directly (its main() is guarded); only its pure functions run.

Plus unit tests of the derivation semantics on a synthetic corpus.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GAP_MSSRV = REPO_ROOT / "Gap" / "MSSRV"

from pysc.gap import analyze_folder  # noqa: E402
from pysc.gap.engine import GapError, _covered_map  # noqa: E402
from pysc.gap.extract import (  # noqa: E402
    extract_active_checks,
    extract_control_number,
    extract_inactive_checks,
)
from pysc.nist.oscal import OscalCatalog, normalize_control_id  # noqa: E402


@pytest.fixture(scope="module")
def legacy_gap():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import NIST_audit_Gap_Analysis as legacy

    return legacy


@pytest.fixture(scope="module")
def catalog():
    return OscalCatalog.load(REPO_ROOT / "NIST_SP-800-53_rev5_catalog.json")


PARITY_FILES = [
    "MSSRV_Baseline.audit",
    "CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_MS.audit",
]


@pytest.mark.parametrize("name", PARITY_FILES)
def test_active_extraction_matches_legacy(legacy_gap, name):
    path = str(GAP_MSSRV / name)
    ours = extract_active_checks(path)
    theirs = legacy_gap.extract_audit_items(path)
    assert len(ours) == len(theirs)
    for a, b in zip(ours, theirs):
        assert a["control_number"] == b["control_number"]
        assert a["description"] == b["description"]
        assert set(a["controls"]) == set(b["controls"])


def test_inactive_extraction_matches_legacy(legacy_gap):
    path = str(GAP_MSSRV / "MSSRV_Baseline.audit")
    ours = extract_inactive_checks(path)
    theirs = legacy_gap.extract_inactive_audit_items(path)
    assert len(ours) == len(theirs)
    for a, b in zip(ours, theirs):
        assert a["control_number"] == b["control_number"]
        assert a["controls"] == b["controls"]


def test_rollup_matches_legacy(legacy_gap, catalog):
    path = str(GAP_MSSRV / "MSSRV_Baseline.audit")
    items = extract_active_checks(path)
    target = catalog.base_controls("full")
    theirs = legacy_gap.analyze_single_file(items, target, catalog.parents)
    ours = _covered_map(items, catalog)
    assert set(ours.keys()) == set(theirs.keys())
    for key in ours:
        assert ours[key] == theirs[key], f"rule list mismatch for {key}"


def test_oscal_catalog_loads(catalog):
    assert catalog.controls["AC-2"]
    assert catalog.parent_of("AC-2(1)") == "AC-2"
    base = catalog.base_controls("full")
    assert "AC-2" in base
    assert not any("(" in k for k in base)
    assert catalog.family_of("SC-7") == ("SC", "System and Communications Protection")


def test_baseline_profiles_not_available(catalog):
    from pysc.nist.oscal import OscalError

    with pytest.raises(OscalError):
        catalog.base_controls("moderate")


def test_normalize_control_id():
    assert normalize_control_id("ac-02") == "AC-2"
    assert normalize_control_id("AC-2(1)") == "AC-2(1)"


def test_extract_control_number():
    assert extract_control_number("18.9.13.1 Ensure thing") == "18.9.13.1"
    assert extract_control_number("1.0022 - MSSRV - Something") == "1.0022"


# --- Synthetic derivation tests ----------------------------------------------

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


@pytest.fixture()
def synthetic_dir(tmp_path):
    (tmp_path / "TEST_Baseline.audit").write_text(BASELINE_AUDIT, encoding="utf-8")
    (tmp_path / "CIS_Candidate.audit").write_text(CANDIDATE_AUDIT, encoding="utf-8")
    return tmp_path


def test_derivation_semantics(synthetic_dir):
    analysis = analyze_folder(
        synthetic_dir,
        catalog_path=REPO_ROOT / "NIST_SP-800-53_rev5_catalog.json",
        baseline_name="TEST_Baseline.audit",
    )
    assert analysis.baseline.short_name == "TEST_Baseline.audit"
    assert "AC-2" in analysis.baseline_covered_set
    # IA-5 and SC-7 are covered by the candidate but not the active baseline.
    assert analysis.coverage_opportunities == {"IA-5", "SC-7"}
    # IA-5 exists commented-out in the baseline -> recoverable by un-commenting.
    assert analysis.inactive_coverage_opportunities == {"IA-5"}
    # SC-7 requires importing a check from the candidate.
    assert analysis.additional_controls_not_present == {"SC-7"}
    rows = analysis.inactive_opportunity_rows
    assert len(rows) == 1 and rows[0]["rule_id"] == "1.0002"


def test_missing_baseline_is_explicit_error(tmp_path):
    (tmp_path / "CIS_Candidate.audit").write_text(CANDIDATE_AUDIT, encoding="utf-8")
    with pytest.raises(GapError):
        analyze_folder(
            tmp_path,
            catalog_path=REPO_ROOT / "NIST_SP-800-53_rev5_catalog.json",
        )


def test_harvest_roundtrip(tmp_path):
    from pysc.gap import harvest

    (tmp_path / "CIS_Candidate.audit").write_text(CANDIDATE_AUDIT, encoding="utf-8")
    (tmp_path / "controls.txt").write_text("2.1\n2.2\n", encoding="utf-8")
    baseline = tmp_path / "TEST_Baseline.audit"
    baseline.write_text(BASELINE_AUDIT, encoding="utf-8")

    out, count, skipped = harvest(
        tmp_path, baseline_path=baseline, output_file=tmp_path / "out.audit"
    )
    text = out.read_text(encoding="utf-8")
    # 2.2 (SC-7) harvested; 2.1 (IA-5) not suppressed either since the active
    # baseline only covers AC-2 -> both blocks present, none skipped.
    assert count == 2 and not skipped
    assert 'see_also                 : "See HTH Policies and Standards"' in text
    assert '"NIST 800-53r5|SC-7"' in text
