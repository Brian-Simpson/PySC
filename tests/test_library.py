"""Control-library tests.

The anchor case comes from the program owner: 'Maximum password age' audited
three different ways (native PASSWORD_POLICY, net-accounts PowerShell, secedit
PowerShell) across three files MUST collapse to a single library entry keyed
by what is audited, with each file's expectation recorded on the entry.
"""

from pathlib import Path

from pysc.library import build_library, check_audit_file, load_library
from pysc.library.build import (
    duplicates_in_file,
    expectation_variances,
    latest_normalized,
    save_library,
)

NATIVE_FILE = '''<check_type:"Windows" version:"2">
#<variable>
#  <name>MAXIMUM_PASSWORD_AGE</name>
#  <default>[1..365]</default>
#</variable>
<custom_item>
  type            : PASSWORD_POLICY
  description     : "1.1.2 Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
  info            : "This policy setting defines how long a user can use their password before it expires."
  reference       : "800-171|3.5.2,800-53r5|IA-5(1),CSCv8|5.2,LEVEL|1A"
  value_type      : TIME_DAY
  value_data      : @MAXIMUM_PASSWORD_AGE@
  password_policy : MAXIMUM_PASSWORD_AGE
</custom_item>
</check_type>
'''

NET_ACCOUNTS_FILE = '''<check_type:"Windows" version:"2">
<custom_item>
  type            : AUDIT_POWERSHELL
  description     : "1.0003 - MSWRK - Ensure Maximum password age is set to 365 or fewer days, but not 0"
  info            : "This policy setting defines how long a user can use their password before it expires."
  reference       : "NIST 800-53r5|IA-5(1)"
  value_type      : POLICY_TEXT
  value_data      : "0"
  powershell_args : "-NoProfile -ExecutionPolicy Bypass -Command '$__pysc_result = (& { $MaxPwdObj = net accounts | Select-string ''Maximum password age''; $MaxPwdStr = $MaxPwdObj.ToString(); Write-Output $MaxPwdStr; } | Out-String)'"
</custom_item>
</check_type>
'''

SECEDIT_FILE = '''<check_type:"Windows" version:"2">
<custom_item>
  type            : AUDIT_POWERSHELL
  description     : "1.0004 - MSWRK - Ensure Maximum password age is set to 365 or fewer days, but not 0"
  info            : "This policy setting defines how long a user can use their password before it expires."
  reference       : "NIST 800-53r5|IA-5(1)"
  value_type      : POLICY_TEXT
  value_data      : "60"
  powershell_args : $tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp /quiet; $val = (Get-Content $tmp | Where-Object { $_ -match '^MaximumPasswordAge\\s*=' } | Select-Object -Last 1) -replace '.*=\\s*',''; Remove-Item $tmp -Force; if ($val -ne '') { $val.Trim() } else { 'NOT_FOUND' }
</custom_item>
</check_type>
'''

EXPECTED_KEY = "PASSWORD_POLICY:MAXIMUM_PASSWORD_AGE"


def _write_three(tmp_path):
    files = {
        "CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit": NATIVE_FILE,
        "CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1_BL_26083111.audit": NET_ACCOUNTS_FILE,
        "HTH_MSWRK_BASELINE.audit": SECEDIT_FILE,
    }
    paths = []
    for name, content in files.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths


def test_three_mechanics_one_control(tmp_path):
    entries = build_library(_write_three(tmp_path))
    assert list(entries.keys()) == [EXPECTED_KEY]
    entry = entries[EXPECTED_KEY]
    assert len(entry["occurrences"]) == 3
    assert entry["types"] == {"PASSWORD_POLICY", "AUDIT_POWERSHELL"}
    assert set(entry["expectations"]) == {"[1..365]", "0", "60"}
    assert entry["nist_refs"] == {"IA-5(1)"}
    # Different expectations -> variance finding, not separate controls.
    variances = expectation_variances(entries)
    assert len(variances) == 1 and variances[0][0] == EXPECTED_KEY
    # No in-file duplicates here.
    assert duplicates_in_file(entries) == []


def test_library_roundtrip_and_check(tmp_path):
    entries = build_library(_write_three(tmp_path))
    lib_path = tmp_path / "control_library.json"
    save_library(entries, lib_path)
    controls = load_library(lib_path)
    assert EXPECTED_KEY in controls
    assert controls[EXPECTED_KEY]["expectations"] == {"[1..365]": 1, "0": 1, "60": 1}

    # KNOWN: same audited item, expectation already in the library.
    known = tmp_path / "known.audit"
    known.write_text(SECEDIT_FILE, encoding="utf-8")
    rows = check_audit_file(controls, known)
    assert [r["status"] for r in rows] == ["KNOWN"]

    # EXPECTATION_DIFFERS: known item, unseen expectation.
    differs = tmp_path / "differs.audit"
    differs.write_text(SECEDIT_FILE.replace('"60"', '"90"'), encoding="utf-8")
    rows = check_audit_file(controls, differs)
    assert [r["status"] for r in rows] == ["EXPECTATION_DIFFERS"]

    # NEW: audited item absent from the library.
    new = tmp_path / "new.audit"
    new.write_text(
        NATIVE_FILE.replace("MAXIMUM_PASSWORD_AGE", "MINIMUM_PASSWORD_LENGTH")
        .replace("[1..365]", "[14..128]"),
        encoding="utf-8",
    )
    rows = check_audit_file(controls, new)
    assert [r["status"] for r in rows] == ["NEW"]

    # DUPLICATE_IN_FILE: the same audited item twice in one audit.
    duped = tmp_path / "duped.audit"
    duped.write_text(SECEDIT_FILE + "\n" + NET_ACCOUNTS_FILE, encoding="utf-8")
    rows = check_audit_file(controls, duped)
    assert [r["status"] for r in rows] == ["KNOWN", "DUPLICATE_IN_FILE"]


def test_latest_normalized_picks_newest_generation(tmp_path):
    norm = tmp_path / "Normalized"
    norm.mkdir()
    (norm / "CIS_Thing_v1.0.0_L1_26081309.audit").write_text("old", encoding="utf-8")
    (norm / "CIS_Thing_v1.0.0_L1_26083111.audit").write_text("new", encoding="utf-8")
    (norm / "CIS_Other_v2.0.0_L1_26083111.audit").write_text("x", encoding="utf-8")
    picked = latest_normalized(norm)
    names = sorted(p.name for p in picked)
    assert names == [
        "CIS_Other_v2.0.0_L1_26083111.audit",
        "CIS_Thing_v1.0.0_L1_26083111.audit",
    ]


def test_policy_variance_lifecycle(tmp_path):
    from pysc.library.policy import classify_variances, load_register, seed_register

    prod = tmp_path / "prod"
    vendor = tmp_path / "vendor"
    prod.mkdir()
    vendor.mkdir()
    (vendor / "CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit").write_text(
        NATIVE_FILE, encoding="utf-8"
    )
    baseline = prod / "HTH_MSWRK_BASELINE.audit"
    baseline.write_text(SECEDIT_FILE, encoding="utf-8")

    entries = build_library([vendor / "CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit", baseline])
    register_path = tmp_path / "policy_variances.toml"

    # Baselines agree on 60, vendor says [1..365], nothing approved yet.
    rows = classify_variances(entries, {}, prod)
    assert len(rows) == 1
    assert rows[0]["status"] == "NEEDS_POLICY_DECISION"
    assert rows[0]["baseline_values"] == {"60": 1}

    # Seeding proposes the baseline value as the approved policy.
    candidates, conflicts = seed_register(entries, {}, prod, register_path)
    assert len(candidates) == 1 and not conflicts
    register = load_register(register_path)
    assert register[EXPECTED_KEY]["approved"] == "60"

    # With the approval recorded, the variance is APPROVED_POLICY.
    rows = classify_variances(entries, register, prod)
    assert rows[0]["status"] == "APPROVED_POLICY"

    # A second baseline that disagrees becomes a policy conflict.
    rebel = prod / "HTH_MSSRV_BASELINE.audit"
    rebel.write_text(SECEDIT_FILE.replace('"60"', '"90"'), encoding="utf-8")
    entries2 = build_library(
        [vendor / "CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit", baseline, rebel]
    )
    rows = classify_variances(entries2, register, prod)
    assert rows[0]["status"] == "CONFLICTS_WITH_POLICY"

    # ...and without any approval it is a BASELINE_CONFLICT.
    rows = classify_variances(entries2, {}, prod)
    assert rows[0]["status"] == "BASELINE_CONFLICT"


def test_ratify_and_cis_variance_register(tmp_path):
    from pysc.library.policy import (
        cis_variance_rows,
        classify_variances,
        load_register,
        ratify_baselines,
    )

    prod = tmp_path / "prod"
    vendor = tmp_path / "vendor"
    norm = prod / "Normalized"
    prod.mkdir()
    vendor.mkdir()
    norm.mkdir()
    cis = vendor / "CIS_Microsoft_Windows_11_Enterprise_v5.0.0_L1_BL.audit"
    cis.write_text(NATIVE_FILE, encoding="utf-8")
    baseline = prod / "HTH_MSWRK_BASELINE.audit"
    baseline.write_text(SECEDIT_FILE, encoding="utf-8")
    # Normalized derivative re-encodes the expectation - must NOT count as a
    # second baseline opinion (this caused the false conflicts).
    derived = norm / "HTH_MSWRK_BASELINE_26083111.audit"
    derived.write_text(SECEDIT_FILE.replace('"60"', '"^(60)$"'), encoding="utf-8")

    entries = build_library([cis, baseline, derived])
    rows = classify_variances(entries, {}, prod)
    assert rows[0]["status"] == "NEEDS_POLICY_DECISION"
    assert rows[0]["baseline_values"] == {"60": 1}

    register_path = tmp_path / "policy_variances.toml"
    ratified, conflicts = ratify_baselines(entries, {}, prod, register_path)
    assert ratified == [EXPECTED_KEY] and not conflicts
    register = load_register(register_path)
    assert register[EXPECTED_KEY]["approved"] == "60"

    # Hand-curated rationales survive re-ratification.
    register[EXPECTED_KEY]["rationale"] = "HTH Password Standard 4.1"
    from pysc.library.policy import write_register

    write_register(register, register_path)
    ratified, _ = ratify_baselines(entries, load_register(register_path), prod, register_path)
    assert ratified == []  # already ratified with curated rationale
    assert load_register(register_path)[EXPECTED_KEY]["rationale"] == "HTH Password Standard 4.1"

    # Deviation register: HTH 60 differs from the CIS recommendation [1..365].
    cis_rows = cis_variance_rows(entries, load_register(register_path), prod, vendor)
    assert len(cis_rows) == 1
    row = cis_rows[0]
    assert row["key"] == EXPECTED_KEY
    assert row["hth_value"] == "60"
    assert row["cis_values"] == "[1..365]"
    assert "CIS_Microsoft_Windows_11" in row["cis_sources"]
    assert row["rationale"] == "HTH Password Standard 4.1"
