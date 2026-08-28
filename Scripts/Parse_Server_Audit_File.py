import re
import sys
import os
import shutil
import subprocess
from datetime import datetime

def normalize_commented_metadata(content):
    """Preserve type/name/profile/version and variable defaults as header comments."""
    spec = {}
    variables = []
    current_variable = None
    cleaned_lines = []
    in_ui_metadata = False
    in_spec = False
    in_variables = False
    in_variable = False

    for line in content.splitlines():
        stripped = line.lstrip()

        if stripped.startswith('#<ui_metadata>'):
            in_ui_metadata = True
            continue
        if stripped.startswith('#</ui_metadata>'):
            in_ui_metadata = False
            if in_variable and current_variable:
                variables.append(current_variable)
                current_variable = None
            in_variable = False
            in_spec = False
            in_variables = False
            continue

        if in_ui_metadata:
            comment_text = stripped[1:].strip()
            if comment_text.startswith('<spec>'):
                in_spec = True
                continue
            if comment_text.startswith('</spec>'):
                in_spec = False
                continue
            if comment_text.startswith('<variables>'):
                in_variables = True
                continue
            if comment_text.startswith('</variables>'):
                in_variables = False
                if in_variable and current_variable:
                    variables.append(current_variable)
                    current_variable = None
                in_variable = False
                continue

            if in_spec:
                match = re.match(r'^<(?P<tag>\w+)>(?P<value>.*?)</(?P=tag)>', comment_text)
                if match:
                    spec[match.group('tag').lower()] = match.group('value').strip()
                continue

            if in_variables:
                if comment_text.startswith('<variable>'):
                    in_variable = True
                    current_variable = {}
                    continue
                if comment_text.startswith('</variable>'):
                    in_variable = False
                    if current_variable:
                        variables.append(current_variable)
                        current_variable = None
                    continue
                if in_variable:
                    match = re.match(r'^<(?P<tag>\w+)>(?P<value>.*?)</(?P=tag)>', comment_text)
                    if match:
                        current_variable[match.group('tag').lower()] = match.group('value').strip()
                continue

            continue

        if stripped.startswith('#'):
            continue

        cleaned_lines.append(line)

    header_comments = []
    if spec:
        for field in ['type', 'name', 'profile', 'version']:
            if field in spec:
                header_comments.append(f"#  <{field}>{spec[field]}</{field}>")
        header_comments.append('')

    if variables:
        header_comments.append('#  <variables>')
        for variable in variables:
            header_comments.append('#    <variable>')
            for field in ['name', 'default', 'description', 'info', 'value_type']:
                if field in variable:
                    header_comments.append(f"#      <{field}>{variable[field]}</{field}>")
            header_comments.append('#    </variable>')
        header_comments.append('#  </variables>')
        header_comments.append('')

    output = '\n'.join(header_comments + cleaned_lines)
    defaults = {v['name']: v.get('default', '') for v in variables if 'name' in v}
    return output, defaults


def substitute_variable_placeholders(content, variable_defaults):
    if not variable_defaults:
        return content

    pattern = re.compile(r'@(' + '|'.join(re.escape(name) for name in variable_defaults) + r')@')

    def replace(match):
        return variable_defaults.get(match.group(1), match.group(0))

    return pattern.sub(replace, content)


def replace_autoadminlogon_defaultpassword_pairs(content):
    pattern = re.compile(
        r'(<condition\s+auto:"FAILED"\s+type:"AND"\s*>\s*)'
        r'<custom_item>\s*'
        r'type\s*:\s*REGISTRY_SETTING\s*\n'
        r'description\s*:\s*"Ensure \'AutoAdminLogon\' is \'Windows: Registry Value\' to \'0\'"\s*\n'
        r'value_type\s*:\s*POLICY_TEXT\s*\n'
        r'value_data\s*:\s*"0"\s*\n'
        r'reg_key\s*:\s*"(?P<reg_key>[^"]+)"\s*\n'
        r'reg_item\s*:\s*"AutoAdminLogon"\s*\n'
        r'reg_option\s*:\s*CAN_BE_NULL\s*\n'
        r'</custom_item>\s*\n'
        r'<custom_item>\s*\n'
        r'type\s*:\s*REG_CHECK\s*\n'
        r'description\s*:\s*"Ensure \'DefaultPassword\' does not exist"\s*\n'
        r'value_type\s*:\s*POLICY_TEXT\s*\n'
        r'value_data\s*:\s*"(?P<check_key>[^"]+)"\s*\n'
        r'reg_option\s*:\s*MUST_NOT_EXIST\s*\n'
        r'key_item\s*:\s*"DefaultPassword"\s*\n'
        r'</custom_item>\s*'
        r'(?=</condition>)',
        re.DOTALL | re.IGNORECASE,
    )

    def replacement(match):
        reg_key = match.group('reg_key')
        escaped_reg_key = reg_key.replace('\\', '\\\\')
        return (
            f"{match.group(1)}<custom_item>\n"
            "      type                 : AUDIT_POWERSHELL\n"
            "      description          : \"Ensure AutoAdminLogon is 0 and DefaultPassword does not exist\"\n"
            "      info                 : \"Evaluates automatic administrative logon configurations to ensure credentials are not cached or exposed.\"\n"
            "      solution             : \"Set 'AutoAdminLogon' to '0' and delete the 'DefaultPassword' registry value under {escaped_reg_key}.\"\n"
            "      reference            : \"NIST SP 800-53 Rev. 5|IA-2\"\n"
            "      value_type           : POLICY_TEXT\n"
            "      value_data           : \"PASSED\"\n"
            "      powershell_args      : \"$p='HKLM:\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon'; $c1=$false; $c2=$false; if (Test-Path $p) { $a=Get-ItemProperty -Path $p -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue; if ($null -ne $a -and $a.AutoAdminLogon -ne '0') { $c1=$true }; $d=Get-ItemProperty -Path $p -Name 'DefaultPassword' -ErrorAction SilentlyContinue; if ($null -ne $d) { $c2=$true } }; if ($c1 -and $c2) { Write-Output 'FAILED' } else { Write-Output 'PASSED' }\"\n"
            "    </custom_item>"
        )

    return pattern.sub(replacement, content)


def process_audit_content(content):
    """
    Parses the file sequentially to maintain structure, including <if>, <then>, 
    <else>, and collapses multi-line text strings to prevent syntax crashes.
    """
    fields_to_collapse = ['description', 'info', 'solution', 'see_also']
    for field in fields_to_collapse:
        pattern = re.compile(rf'({field}\s*:\s*")([^"]*?)(")', re.DOTALL)
        def collapse_match(m):
            cleaned_text = re.sub(r'\s+', ' ', m.group(2)).strip()
            return f'{m.group(1)}{cleaned_text}{m.group(3)}'
        content = pattern.sub(collapse_match, content)

    content = re.sub(
        r'(see_also\s*:\s*")[^"]*(")',
        r'\1See HTH Policies and Standards\2',
        content,
        flags=re.IGNORECASE,
    )

    content = replace_autoadminlogon_defaultpassword_pairs(content)

    block_pattern = re.compile(
        r'(<custom_item>.*?</custom_item>|<if>|<then>|</then>|<else>|</else>|</if>|<check_type[^>]*>|</check_type>|<group_policy[^>]*>|</group_policy>)', 
        re.DOTALL
    )

    output_lines = []
    last_index = 0
    for match in block_pattern.finditer(content):
        prefix = content[last_index:match.start()]
        if prefix.strip():
            output_lines.append(prefix.strip())
        token = match.group(0)
        token_strip = token.strip()
        if not token_strip.startswith('<custom_item>'):
            output_lines.append(token_strip)
        else:
            item_dict = {}
            lines = token_strip.replace('<custom_item>', '').replace('</custom_item>', '').strip().split('\n')
            for line in lines:
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    if key == 'value_data' and '||' in val:
                        item_dict[key] = val.replace('"', '').strip()
                    else:
                        if val.startswith('"') and val.endswith('"'):
                            val = val[1:-1]
                        item_dict[key] = val
            if item_dict:
                converted_block = convert_item_to_powershell(item_dict)
                output_lines.append(converted_block)
        last_index = match.end()

    remainder = content[last_index:]
    if remainder.strip():
        output_lines.append(remainder.strip())

    if not output_lines:
        return content

    return "\n\n".join(output_lines)

def should_emit_can_be_null(item, check_type, ps_args):
    """Return True when the generated PowerShell check may legitimately yield null/empty output."""
    if not ps_args:
        return False

    if check_type == 'AUDIT_POWERSHELL':
        return False

    normalized_ps_args = ps_args.lower()

    if check_type == 'REGISTRY_SETTING':
        return True

    if check_type == 'USER_RIGHTS_POLICY':
        return True

    if check_type == 'PASSWORD_POLICY':
        return False

    null_indicators = [
        'erroraction silentlycontinue',
        'test-path',
        'get-itemproperty',
        'get-item ',
        'get-childitem',
        'get-content',
        'select-object -last 1',
        'where-object',
        'if([string]::isnullorwhitespace',
        'if ($null -eq',
        'if (-not (test-path',
    ]

    return any(indicator in normalized_ps_args for indicator in null_indicators)


def escape_audit_string(value):
    if value is None:
        return ''
    value = str(value)
    return value.replace('\\', '\\\\').replace('"', '\\"')


def validate_with_auditutils(output_path):
    """Validate the generated audit file with Tenable auditutils via Docker when available."""
    if not output_path or not os.path.exists(output_path):
        return False, 'Output file was not created.'

    docker_exe = shutil.which('docker')
    if not docker_exe:
        return False, 'Docker is not available.'

    output_dir = os.path.dirname(output_path) or '.'
    output_name = os.path.basename(output_path)
    cmd = [
        docker_exe,
        'run',
        '--rm',
        '-v',
        f'{output_dir}:/data',
        'tenable/audit-utils:latest',
        '/bin/sh',
        '-lc',
        f'cd /data && audit_tidy /data/{output_name} >/tmp/audit_tidy.out 2>/tmp/audit_tidy.err',
    ]

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        return False, str(exc)

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        return False, detail or 'audit_tidy failed.'

    return True, 'Validated with Tenable auditutils via Docker.'


def truncate_to_sentences(text, max_sentences=4):
    if not text:
        return text

    pattern = re.compile(r'([.!?])(\s+|$)')
    sentences = []
    start = 0

    for match in pattern.finditer(text):
        end = match.end()
        sentences.append(text[start:end].strip())
        start = end
        if len(sentences) >= max_sentences:
            break

    if len(sentences) < max_sentences and start < len(text):
        remainder = text[start:].strip()
        if remainder:
            sentences.append(remainder)

    return ' '.join(sentences[:max_sentences]).strip()


def normalize_reference(reference):
    if not reference:
        return reference

    refs = [ref.strip() for ref in reference.split(',') if ref.strip()]
    r53r5_codes = []
    for ref in refs:
        match = re.match(r'^800-53r5\|(.+)$', ref)
        if match:
            r53r5_codes.extend(code.strip() for code in match.group(1).split() if code.strip())

    if r53r5_codes:
        unique_codes = []
        for code in r53r5_codes:
            if code not in unique_codes:
                unique_codes.append(code)
        return f"NIST 800-53r5|{' '.join(unique_codes)}"

    return reference


def convert_item_to_powershell(item):
    """
    Transforms custom items to AUDIT_POWERSHELL while escaping quotes 
    and correcting native Tenable data logic types to textual responses.
    """
    check_type = item.get('type', '')
    description = escape_audit_string(item.get('description', 'Converted PowerShell Check'))
    info = escape_audit_string(truncate_to_sentences(item.get('info', '')))
    solution = escape_audit_string(truncate_to_sentences(item.get('solution', '')))
    reference = escape_audit_string(normalize_reference(item.get('reference', '')))
    value_data = escape_audit_string(item.get('value_data', ''))
    v_type = "POLICY_TEXT"
    check_type_line = ''
    
    range_match = re.match(r'\[\s*(\d+)\s*\.\.\s*(\d+)\s*\]', value_data)
    ps_range_eval = ""
    if range_match:
        min_val, max_val = range_match.group(1), range_match.group(2)
        ps_range_eval = f" | Where-Object {{ $_ -ge {min_val} -and $_ -le {max_val} }}"
        value_data = "True"
    elif value_data == "MUST_EXIST":
        ps_range_eval = " | ForEach-Object { if($_) { 'True' } else { 'False' } }"
        value_data = "True"

    expect_line = ''
    if check_type == 'AUDIT_POWERSHELL':
        ps_args = item.get('powershell_args', '')
        v_type = item.get('value_type', 'POLICY_TEXT')
    elif check_type == 'REGISTRY_SETTING':
        raw_reg_key = item.get('reg_key', '')
        reg_item = item.get('reg_item', '')
        ps_args = (
            "-NoProfile -ExecutionPolicy Bypass -Command '"
            f"$__pysc_result = (& {{ Write-Output ''REG_CHECK|{reg_item}|{raw_reg_key}''; }} | Out-String); "
            "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output ''__NON_COMPLIANT__'' } else { Write-Output ($__pysc_result.Trim()) }'"
        )
        value_data = raw_reg_key
        v_type = "POLICY_TEXT"
        check_type_line = '\n      check_type          : CHECK_REGEX'
    elif check_type == 'REG_CHECK':
        raw_reg_key = item.get('value_data', '')
        key_item = item.get('key_item', '')
        reg_option = item.get('reg_option', '')
        ps_reg_path = raw_reg_key.replace('HKLM\\', 'HKLM:\\')
        if reg_option == 'MUST_NOT_EXIST':
            ps_args = (
                "-NoProfile -ExecutionPolicy Bypass -Command '"
                f"$p=\"{ps_reg_path}\"; "
                f"if (Test-Path $p) {{ $v = Get-ItemProperty -Path $p -Name '{key_item}' -ErrorAction SilentlyContinue; "
                "if ($null -ne $v) { Write-Output 'EXIST' } else { Write-Output 'NOT_EXIST' } } else { Write-Output 'NOT_EXIST' }'"
            )
            value_data = "NOT_EXIST"
            v_type = "POLICY_TEXT"
            check_type_line = '\n      check_type          : CHECK_REGEX'
        elif reg_option == 'MUST_EXIST':
            ps_args = (
                "-NoProfile -ExecutionPolicy Bypass -Command '"
                f"$p=\"{ps_reg_path}\"; "
                f"if (Test-Path $p) {{ $v = Get-ItemProperty -Path $p -Name '{key_item}' -ErrorAction SilentlyContinue; "
                "if ($null -ne $v) { Write-Output 'EXIST' } else { Write-Output 'NOT_EXIST' } } else { Write-Output 'NOT_EXIST' }'"
            )
            value_data = "EXIST"
            v_type = "POLICY_TEXT"
            check_type_line = '\n      check_type          : CHECK_REGEX'
        else:
            ps_args = f"# Manual conversion required for legacy type: {check_type}"
    elif check_type == 'ANONYMOUS_SID_SETTING':
        value_data = item.get('value_data', '').strip()
        ps_args = (
            "-NoProfile -ExecutionPolicy Bypass -Command '"
            f"$__pysc_result = (& {{ Write-Output ''ANONYMOUS_SID_SETTING|{value_data}''; }} | Out-String); "
            "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output ''__NON_COMPLIANT__'' } else { Write-Output ($__pysc_result.Trim()) }'"
        )
        v_type = "POLICY_TEXT"
        if value_data.startswith('\\b'):
            check_type_line = '\n      check_type          : CHECK_NOT_REGEX'
            expect_line = f'\n      expect              : "{value_data}"'
        elif value_data.lower() in ['enabled', 'disabled', 'true', 'false']:
            check_type_line = '\n      check_type          : CHECK_REGEX'
            expect_line = f'\n      expect              : "{value_data}"'
        else:
            check_type_line = '\n      check_type          : CHECK_EQUAL'
            expect_line = f'\n      expect              : "{value_data}"'
    elif check_type == 'CHECK_ACCOUNT':
        account_type = item.get('account_type', '').upper()
        account_value = item.get('value_data', '').strip()
        if 'GUEST' in account_type:
            if account_value.lower() in ['false', 'disabled']:
                ps_args = (
                    "-NoProfile -ExecutionPolicy Bypass -Command '"
                    "$__pysc_result = (& { $noutput = Get-LocalUser | Where-Object { $_.SID -Match '^S-1-5-21.*-501$' } | Select Name, Enabled; "
                    "if ($noutput -eq $Null) {Write-Output 'Service Not Found'} else {Write-Output $noutput} } | Out-String); "
                    "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
                )
                value_data = account_value
                v_type = "POLICY_TEXT"
                check_type_line = '\n      check_type          : CHECK_EQUAL'
            elif account_value.lower() == 'guest' or account_value.startswith('\\b'):
                ps_args = (
                    "-NoProfile -ExecutionPolicy Bypass -Command '"
                    "$__pysc_result = (& { $A = Get-CimInstance -ClassName Win32_UserAccount -EA SilentlyContinue | Where-Object { $_.SID -match '-501$' } | Select-Object -ExpandProperty Name -First 1; "
                    "if([string]::IsNullOrEmpty($A)){ Write-Output '__NON_COMPLIANT__' } else { Write-Output $A } } | Out-String); "
                    "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
                )
                value_data = account_value
                v_type = "POLICY_TEXT"
                if account_value.startswith('\\b'):
                    check_type_line = '\n      check_type          : CHECK_NOT_REGEX'
                else:
                    check_type_line = '\n      check_type          : CHECK_NOT_EQUAL'
            else:
                ps_args = (
                    "-NoProfile -ExecutionPolicy Bypass -Command '"
                    "$__pysc_result = (& { $A = Get-CimInstance -ClassName Win32_UserAccount -EA SilentlyContinue | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1; "
                    "if($A -and $A.Disabled -ne $null){ if($A.Disabled){ Write-Output 'Disabled' } else { Write-Output 'Enabled' } } elseif($A -and -not [string]::IsNullOrEmpty($A.Name)){ Write-Output $A.Name } else { Write-Output '__NON_COMPLIANT__' } } | Out-String); "
                    "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
                )
                value_data = account_value
                v_type = "POLICY_TEXT"
                check_type_line = '\n      check_type          : CHECK_EQUAL'
        elif 'ADMINISTRATOR' in account_type:
            if account_value.lower() in ['disabled', 'false']:
                ps_args = (
                    "-NoProfile -ExecutionPolicy Bypass -Command '"
                    "$__pysc_result = (& { $A = Get-CimInstance -ClassName Win32_UserAccount -EA SilentlyContinue | Where-Object { $_.SID -match '-500$' } | Select-Object -First 1; "
                    "if($A -and $A.Disabled -ne $null){ if($A.Disabled){ Write-Output 'Disabled' } else { Write-Output 'Enabled' } } elseif($A -and -not [string]::IsNullOrEmpty($A.Name)){ Write-Output $A.Name } else { Write-Output '__NON_COMPLIANT__' } } | Out-String); "
                    "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
                )
                value_data = account_value
                v_type = "POLICY_TEXT"
                check_type_line = '\n      check_type          : CHECK_EQUAL'
            else:
                ps_args = (
                    "-NoProfile -ExecutionPolicy Bypass -Command '"
                    "$__pysc_result = (& { $A = Get-CimInstance -ClassName Win32_UserAccount -EA SilentlyContinue | Where-Object { $_.SID -match '-500$' } | Select-Object -ExpandProperty Name -First 1; "
                    "if([string]::IsNullOrEmpty($A)){ Write-Output '__NON_COMPLIANT__' } else { Write-Output $A } } | Out-String); "
                    "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
                )
                value_data = account_value
                v_type = "POLICY_TEXT"
                if account_value.startswith('\\b'):
                    check_type_line = '\n      check_type          : CHECK_NOT_REGEX'
                else:
                    check_type_line = '\n      check_type          : CHECK_NOT_EQUAL'
        else:
            ps_args = f"# Manual conversion required for legacy type: {check_type}"
            value_data = account_value
            v_type = "POLICY_TEXT"
        if account_value and not ps_args.startswith('# Manual conversion'):
            expect_line = f'\n      expect              : "{account_value}"'
    elif check_type == 'BANNER_CHECK':
        raw_reg_key = item.get('reg_key', '')
        reg_item = item.get('reg_item', '')
        ps_args = (
            "-NoProfile -ExecutionPolicy Bypass -Command '"
            f"$__pysc_result = (& {{ $P = 'Registry::{raw_reg_key}'; $K = '{reg_item}'; "
            "if(-not (Test-Path -Path $P)){ Write-Output '__NON_COMPLIANT__'; return }; "
            "$R = Get-ItemProperty -Path $P -ErrorAction SilentlyContinue; "
            "if($null -eq $R){ Write-Output '__NON_COMPLIANT__'; return }; "
            "$prop = $R.PSObject.Properties[$K]; if($null -eq $prop -or $null -eq $prop.Value){ Write-Output '__NON_COMPLIANT__'; return }; "
            "$V = $prop.Value; if($null -eq $V -or [string]::IsNullOrWhiteSpace([string]$V)){ Write-Output '__NON_COMPLIANT__' } "
            "elseif($V -is [System.Array]){ $joined = ($V -join [Environment]::NewLine); if([string]::IsNullOrWhiteSpace([string]$joined)){ Write-Output '__NON_COMPLIANT__' } else { Write-Output $joined } } else { Write-Output $V; } }} | Out-String); "
            "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output '__NON_COMPLIANT__' } else { Write-Output ($__pysc_result.Trim()) }'"
        )
        value_data = item.get('value_data', '')
        v_type = "POLICY_TEXT"
        check_type_line = '\n      check_type          : CHECK_REGEX'
    elif check_type == 'WMI_POLICY':
        ps_args = "(Get-CimInstance Win32_ComputerSystem).DomainRole"
        if not item.get('info'):
            info = escape_audit_string(
                "Verifies if the system is configured as a standalone server or a member server within a domain."
            )
        if not item.get('solution'):
            solution = escape_audit_string(
                "If the role is incorrect, join the server to the appropriate workgroup or domain."
            )
        if not item.get('reference'):
            reference = escape_audit_string("NIST SP 800-53 Rev. 5 | CM-6 CM-8")
        v_type = "POLICY_TEXT"
    elif check_type == 'LOCKOUT_POLICY':
        policy_name = item.get('lockout_policy', '')
        policy_map = {
            'LOCKOUT_DURATION': 'Lockout duration',
            'LOCKOUT_THRESHOLD': 'Lockout threshold',
            'LOCKOUT_RESET': 'Reset account lockout counter after',
        }
        search_str = policy_map.get(policy_name)
        if search_str:
            raw_value = item.get('value_data', '')
            target_value = raw_value
            if raw_value.isdigit():
                target_value = raw_value
            else:
                numeric_match = re.search(r'(\d+)', raw_value)
                if numeric_match:
                    target_value = numeric_match.group(1)

            if not target_value:
                target_value = raw_value

            ps_args = (
                "-NoProfile -ExecutionPolicy Bypass -Command '"
                f"$__pysc_result = (& {{ $Obj = net accounts | Select-String ''{search_str}''; "
                f"$Str = $Obj.ToString(); $Str -match ''\\d{{1,3}}'' | Out-Null; "
                f"$Str -match ''{target_value}'' | Out-Null; $LO = $matches[0]; Write-Output $LO; }} | Out-String); "
                "if([string]::IsNullOrWhiteSpace([string]$__pysc_result){ Write-Output ''__NON_COMPLIANT__'' } else { Write-Output ($__pysc_result.Trim()) }'"
            )
            value_data = target_value
            v_type = "POLICY_TEXT"
            check_type_line = '\n      check_type          : CHECK_REGEX'
        else:
            ps_args = f"# Manual conversion required for legacy type: {check_type}"
    elif check_type == 'PASSWORD_POLICY':
        policy_name = item.get('password_policy', '')
        if policy_name == 'LOCKOUT_ADMINS':
            ps_args = (
                "-NoProfile -ExecutionPolicy Bypass -Command '"
                "$__pysc_result = (& { $secfile = [System.IO.Path]::GetTempFileName(); "
                "secedit /export /cfg $secfile /areas SECURITYPOLICY /quiet | Out-Null; "
                "$line = Select-String -Path $secfile -Pattern ''AllowAdministratorLockout\s*=\s*(\d)'' | Select-Object -First 1; "
                "Remove-Item $secfile -ErrorAction SilentlyContinue; "
                "if($line -and $line.Matches.Count -gt 0){ if($line.Matches[0].Groups[1].Value -eq ''1''){ Write-Output ''Enabled'' } else { Write-Output ''Disabled'' } } else { Write-Output ''__NON_COMPLIANT__'' } } | Out-String); "
                "if([string]::IsNullOrWhiteSpace([string]$__pysc_result)){ Write-Output ''__NON_COMPLIANT__'' } else { Write-Output ($__pysc_result.Trim()) }'"
            )
            value_data = "(?i)^Enabled$"
            v_type = "POLICY_TEXT"
            check_type_line = '\n      check_type          : CHECK_REGEX'
        else:
            net_accounts_mapping = {
                'ENFORCE_PASSWORD_HISTORY': "password history",
                'MAXIMUM_PASSWORD_AGE': "Maximum password age",
                'MINIMUM_PASSWORD_AGE': "Minimum password age",
                'MINIMUM_PASSWORD_LENGTH': "password length",
            }
            search_str = net_accounts_mapping.get(policy_name)
            if search_str:
                raw_value = item.get('value_data', '')
                target_value = raw_value
                range_match = re.match(r'\[\s*(\d+)\s*\.\.', raw_value)
                if range_match:
                    target_value = range_match.group(1)
                elif raw_value.isdigit():
                    target_value = raw_value
                else:
                    desc_match = re.search(r"'(\d+)", description)
                    if desc_match:
                        target_value = desc_match.group(1)

                if not target_value:
                    target_value = raw_value

                ps_args = (
                    f"-NoProfile -ExecutionPolicy Bypass -Command '"
                    f"$__pysc_result = (& {{ $Obj = net accounts | Select-string ''{search_str}''; "
                    f"$Str = $Obj.ToString(); $Str -match ''\\d{{1,3}}'' | out-null; "
                    f"$Str -match ''{target_value}'' | out-null; $LO = $matches[0]; Write-Output $LO; }} | Out-String); "
                    f"if([string]::IsNullOrWhiteSpace([string]$__pysc_result){{ Write-Output ''__NON_COMPLIANT__'' }} else {{ Write-Output ($__pysc_result.Trim()) }}'"
                )
                value_data = target_value
                v_type = "POLICY_TEXT"
                check_type_line = '\n      check_type          : CHECK_REGEX'
            else:
                mapping = {
                    'MINIMUM_PASSWORD_LENGTH': "Minimum password length",
                    'PASSWORD_HISTORY_SIZE': "Length of password history",
                    'MINIMUM_PASSWORD_AGE': "Minimum password age (days)",
                    'MAXIMUM_PASSWORD_AGE': "Maximum password age (days)",
                    'LOCKOUT_BAD_COUNT': "Lockout threshold"
                }
                search_str = mapping.get(policy_name, "Minimum password length")
                ps_args = f"[int]((net accounts | Select-String '{search_str}') -replace '.*:\\s+','')"
                if ps_range_eval:
                    ps_args = f"if ({ps_args}{ps_range_eval}) {{ 'True' }} else {{ 'False' }}"
    elif check_type == 'AUDIT_POLICY_SUBCATEGORY':
        description_text = item.get('description', '')
        subcategory_name = None
        match = re.search(r"Ensure\s+'(Audit\s+.+?)'", description_text)
        if match:
            subcategory_name = match.group(1)
            if subcategory_name.lower().startswith('audit audit '):
                subcategory_name = subcategory_name[len('audit '):]
        else:
            quote_match = re.search(r"'([^']+)'", description_text)
            if quote_match:
                subcategory_name = quote_match.group(1)
        if not subcategory_name:
            subcategory_name = 'Audit Policy Change'
        ps_args = f"auditpol /get /subcategory:'{subcategory_name}' | Select-String -Pattern 'Success|Failure'"
        value_data = "Success"
    elif check_type == 'USER_RIGHTS_POLICY':
        right_name = item.get('user_right', '')
        ps_args = f"(([WmiClass]'Win32_SecurityDescriptorHelper').GetSecurityDescriptor('{right_name}').Descriptor.Owner.Name)"
        if "||" in value_data:
            value_data = value_data.replace('"', '').strip()
    else:
        ps_args = f"# Manual conversion required for legacy type: {check_type}"

    ps_args_escaped = escape_audit_string(ps_args)
    powershell_option_line = ''
    if should_emit_can_be_null(item, check_type, ps_args):
        powershell_option_line = '\n      powershell_option    : CAN_BE_NULL'

    return f"""    <custom_item>
      type                 : AUDIT_POWERSHELL
      description          : "{description}"
      info                 : "{info}"
      solution             : "{solution}"
      reference            : "{reference}"
      value_type           : {v_type}
      value_data           : "{value_data}"
      powershell_args      : "{ps_args_escaped}"{check_type_line}{expect_line}{powershell_option_line}
    </custom_item>"""

def main():
    print("=== Tenable Audit PowerShell Converter ===")
    
    # Prompt the user for the input file path natively
    input_filename = input("Enter or paste the full path to your source .audit file:\n> ").strip()
    # Strip wrapping quotes if you drag-and-drop the file into the terminal window
    input_filename = input_filename.strip('"').strip("'")

    if not os.path.exists(input_filename):
        print(f"\nError: The input file '{input_filename}' does not exist.")
        input("\nPress Enter to exit...")
        return

    # Automatically derive the output file destination name next to the original file
    dir_name, file_name = os.path.split(input_filename)
    base_name, _ = os.path.splitext(file_name)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    output_filename = os.path.join(dir_name, f"{base_name}_powershell_{timestamp}.audit")

    try:
        with open(input_filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"\nError reading file: {e}")
        input("\nPress Enter to exit...")
        return

    print("\nNormalizing commented metadata and extracting variable defaults...")
    content, variable_defaults = normalize_commented_metadata(content)
    content = substitute_variable_placeholders(content, variable_defaults)

    print("\nParsing file structure and fixing syntax dependencies...")
    final_output = process_audit_content(content)
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(final_output)
        print(f"\nSuccess! New file successfully created at:\n{output_filename}")
    except Exception as e:
        print(f"\nError writing file: {e}")
        input("\nConversion finished. Press Enter to close...")
        return

    validation_ok, validation_message = validate_with_auditutils(output_filename)
    if validation_ok:
        print(f"\n{validation_message}")
    else:
        print(f"\nOptional Tenable validation note: {validation_message}")
        
    input("\nConversion finished. Press Enter to close...")

if __name__ == "__main__":
    main()
