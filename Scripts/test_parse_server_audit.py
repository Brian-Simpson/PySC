import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("parse_server_audit", Path(r"c:\PySC\Parse_Server_Audit_File.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_escape_audit_string_escapes_backslashes_and_quotes():
    value = r'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    escaped = module.escape_audit_string(value)
    assert escaped == r'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'


def test_convert_item_escapes_registry_values_in_output():
    item = {
        'type': 'REG_CHECK',
        'description': 'Check registry value',
        'info': 'Info',
        'solution': 'Solution',
        'reference': 'NIST',
        'value_data': r'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System',
        'key_item': 'DisableBkGndGroupPolicy',
        'reg_option': 'MUST_NOT_EXIST',
    }

    converted = module.convert_item_to_powershell(item)
    assert 'value_data           : "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System"' in converted
    assert 'powershell_args      : "-NoProfile' in converted
