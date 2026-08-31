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
