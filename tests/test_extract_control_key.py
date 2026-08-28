from pathlib import Path
import sys

# Ensure workspace root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Consolidate_Framework_Baselines import extract_control_key


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
