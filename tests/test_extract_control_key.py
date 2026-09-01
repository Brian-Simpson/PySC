from pathlib import Path
import sys

import pytest

# The module under test was a legacy Scripts\ utility, retired to TAPARCHIVE;
# its dashboard logic was superseded by pysc.report. Skip when absent.
_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "Scripts"
if not (_SCRIPTS_DIR / "Consolidate_Framework_Baselines.py").is_file():
    pytest.skip(
        "legacy Scripts/Consolidate_Framework_Baselines retired (TAPARCHIVE)",
        allow_module_level=True,
    )
sys.path.insert(0, str(_SCRIPTS_DIR))

from Consolidate_Framework_Baselines import extract_control_key


@pytest.mark.xfail(
    reason=(
        "Documents intended behavior that legacy extract_control_key no longer "
        "implements: standalone calls return the quoted property ('MaxSize') "
        "because the path-prefixed key only emerges after the pipeline prepass "
        "marks the property as a duplicate, and even then it is quoted/mixed-"
        "case. To be fixed when this logic is lifted into pysc.report (Phase 4)."
    ),
    strict=True,
)
def test_windows_eventlog_maxsize():
    row = {
        "powershell_args": "$p = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' -ErrorAction SilentlyContinue; $val = if ($p -and $p.PSObject.Properties['MaxSize'] -ne $null) { [int]$p.'MaxSize' } else { 0 }; [string]$val",
        "Source_File": "HTH_MSWRK_BASELINE.audit"
    }
    res = extract_control_key(row)
    print('Mapped control key:', res)
    assert res == 'Windows_EventLog_Application MAXSIZE'


if __name__ == '__main__':
    test_windows_eventlog_maxsize()
    print('OK')
