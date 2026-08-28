#!/usr/bin/env python3
"""Process_MSServer.py

Combined pipeline for Windows Server audit files:
  Step 1 — Normalize    (fields cleaned, keys classified, descriptions numbered)
  Step 2 — Convert      (flatten if/then/else, convert custom_items to AUDIT_POWERSHELL)
  Step 3 — Renumber     (sequential 1.XXXX - MSSVR - numbers)

Outputs:
  {base}-normalized.audit
  {base}-normalized-converted.audit   (final, renumbered in place)
"""

import os
import re
from collections import OrderedDict

# =============================================================================
# CONFIGURATION
# =============================================================================

OUTPUT_DIR = r"C:\PySC"

REAL_KEYS = {
    "type", "description", "info", "reference", "see_also",
    "api_request_type", "request", "xsl_stmt", "not_expect",
    "powershell_args", "key_item",
    "value_type", "value_data", "reg_key", "reg_item", "reg_option",
    "audit_policy_subcategory", "right_type", "reg_include_hku_users",
    "check_type", "account_type", "password_policy", "lockout_policy",
    "regex", "expect",
    "wmi_namespace", "wmi_request", "wmi_attribute", "wmi_key",
    "match_all",
    "sql_expect",
    "sql_request",
    "sql_types",
}

IGNORED_KEYS = {
    "solution",
    "Impact",
    "Note",
    "Caution",
    "Disabled",
    "Enabled",
    "Example",
    "Important",
    "Warning",
    "NOTE",
    "https",
    "4944",
    "4945",
    "4946",
    "4947",
    "4948",
    "4949",
    "4950",
    "4951",
    "4952",
    "4953",
    "4954",
    "4956",
    "4957",
    "4958",
    "5063",
    "5064",
    "5065",
    "5066",
    "5067",
    "5068",
    "5069",
    "5070",
    "6145",
}

SEE_ALSO_REPLACEMENT = "See HTH Policies and Standards"

# =============================================================================
# SECEDIT MAPPINGS
# =============================================================================

LOCKOUT_SECEDIT = {
    "LOCKOUT_DURATION":  "LockoutDuration",
    "LOCKOUT_THRESHOLD": "LockoutBadCount",
    "LOCKOUT_RESET":     "ResetLockoutCount",
}

PASSWORD_SECEDIT = {
    "ENFORCE_PASSWORD_HISTORY": "PasswordHistorySize",
    "MAXIMUM_PASSWORD_AGE":     "MaximumPasswordAge",
    "MINIMUM_PASSWORD_AGE":     "MinimumPasswordAge",
    "MINIMUM_PASSWORD_LENGTH":  "MinimumPasswordLength",
    "COMPLEXITY_REQUIREMENTS":  "PasswordComplexity",
    "REVERSIBLE_ENCRYPTION":    "ClearTextPassword",
    "FORCE_LOGOFF":             "ForceLogoffWhenHourExpire",
    "LOCKOUT_ADMINS":           "AllowAdministratorLockout",
}

# =============================================================================
# SHARED HELPERS
# =============================================================================

def resolve_variables(text, variables):
    for k, v in variables.items():
        text = text.replace(f"@{k}@", v)
    return text


def normalize_info(raw):
    if not raw:
        return None
    s = raw.strip()
    s = re.sub(r'^[\'"]+', '', s)
    s = re.sub(r'[\'"]+$', '', s)
    s = re.sub(r'\s+', ' ', s)
    sentence = s.split('.')[0].strip()
    if not sentence:
        return None
    return f'"{sentence}."'


def normalize_reference(raw):
    if not raw:
        return None
    flat = re.sub(r"\s+", " ", raw)
    parts = [p.strip() for p in flat.split(",")]
    controls = []
    for p in parts:
        m = re.match(r"^800-53r5\|(.+)$", p)
        if m:
            controls.append(m.group(1))
    if not controls:
        return None
    seen = set()
    unique = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return '"NIST 800-53r5|' + " ".join(unique) + '"'


def unquote(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def reg_path(reg_key):
    reg_key = unquote(reg_key)
    mapping = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKCU": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKU":  "HKEY_USERS",
        "HKCC": "HKEY_CURRENT_CONFIG",
    }
    for short, full in mapping.items():
        if reg_key.upper().startswith(short + "\\"):
            reg_key = full + reg_key[len(short):]
            break
    return "Registry::" + reg_key


def align_colons(lines):
    """Align all key : value separators to the same column across the file."""
    kv_re = re.compile(r'^(\s*)([A-Za-z0-9_]+)(\s+): ')
    max_col = 0
    for line in lines:
        m = kv_re.match(line)
        if m:
            col = len(m.group(1)) + len(m.group(2)) + len(m.group(3))
            if col > max_col:
                max_col = col
    result = []
    for line in lines:
        m = kv_re.match(line)
        if m:
            indent = m.group(1)
            key = m.group(2)
            rest = line[len(indent) + len(key) + len(m.group(3)):]
            padding = max_col - len(indent) - len(key)
            result.append(f"{indent}{key}{' ' * padding}{rest}")
        else:
            result.append(line)
    return result


def normalize_custom_item_indent(content):
    """Re-indent every <custom_item>...</custom_item> block: tags at 0, fields at 2 spaces."""
    lines = content.splitlines()
    result = []
    in_item = False
    for line in lines:
        stripped = line.strip()
        if stripped == '<custom_item>':
            in_item = True
            result.append('<custom_item>')
        elif stripped == '</custom_item>':
            in_item = False
            result.append('</custom_item>')
        elif in_item:
            result.append(('  ' + stripped) if stripped else '')
        else:
            result.append(line)
    return '\n'.join(result) + '\n'

# =============================================================================
# PERSIST KEY HELPER
# =============================================================================

def _persist_key(key, set_name):
    script = os.path.abspath(__file__)
    with open(script, encoding="utf-8") as f:
        content = f.read()
    pattern = rf'({set_name}\s*=\s*\{{)(.*?)(\}})'
    m = re.search(pattern, content, flags=re.DOTALL)
    if not m:
        print(f"  Could not find {set_name} — add '{key}' manually.")
        return
    prefix, body, closing = m.group(1), m.group(2), m.group(3)
    stripped = body.rstrip()
    if stripped and not stripped.endswith(','):
        body = stripped + ',\n'
    else:
        body = body.rstrip('\n') + '\n'
    new_block = f'{prefix}{body}    "{key}",\n{closing}'
    new_content = content[:m.start()] + new_block + content[m.end():]
    with open(script, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"  '{key}' added to {set_name} in {os.path.basename(script)}.")

# =============================================================================
# STEP 1 — NORMALIZE
# =============================================================================

def extract_variables(lines):
    variables = {}
    current = None
    for line in lines:
        m = re.search(r"<name>(.*?)</name>", line)
        if m:
            current = m.group(1)
            continue
        if current:
            d = re.search(r"<default>(.*?)</default>", line)
            if d:
                variables[current] = d.group(1)
                continue
            if "</variable>" in line:
                current = None
    return variables


def parse_document(lines):
    document = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if re.match(r'\s*<report\b', line):
            m = re.match(r'\s*<report\s+type:"([^"]+)">', line)
            report_type = m.group(1) if m else "PASSED"
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(r'\s*</report>', lines[i]):
                fm = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if fm:
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = fm.group(1)
                    buf = [fm.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            if i < len(lines):
                i += 1  # skip </report>
            document.append({"type": "report", "report_type": report_type, "fields": fields})
            continue

        if re.match(r"\s*(<custom_item>|&lt;custom_item&gt;)", line):
            fields = OrderedDict()
            key = None
            buf = []
            i += 1
            while i < len(lines) and not re.match(
                r"\s*(</custom_item>|&lt;/custom_item&gt;)", lines[i]
            ):
                m = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", lines[i])
                if m:
                    if key:
                        fields[key] = "\n".join(buf).strip()
                    key = m.group(1)
                    buf = [m.group(2)]
                elif key:
                    buf.append(lines[i].rstrip())
                i += 1
            if key:
                fields[key] = "\n".join(buf).strip()
            document.append({"type": "custom_item", "fields": fields})
            i += 1
            continue

        document.append({"type": "text", "text": line})
        i += 1

    return document


def emit_normalize(document, variables):
    output = []
    rendered_blocks = []
    all_keys = []

    after_passed = False
    desc_counter = 1
    unknown_keys = set()

    for node in document:
        if node["type"] == "report" and node["report_type"] == "PASSED":
            after_passed = True
            continue
        if node["type"] != "custom_item":
            continue

        pairs = []
        for k, v in node["fields"].items():
            if k in IGNORED_KEYS:
                continue
            if k not in REAL_KEYS:
                unknown_keys.add(k)
                continue
            if k == "see_also":
                pairs.append((k, f'"{SEE_ALSO_REPLACEMENT}"'))
            elif k == "info":
                info = normalize_info(v)
                if info:
                    pairs.append((k, info))
            elif k == "reference":
                ref = normalize_reference(v)
                if ref:
                    pairs.append((k, ref))
            elif k == "description" and after_passed:
                clean = v.strip().strip('"')
                clean = re.sub(r'^\d+(\.\d+)+\s*', '', clean)
                new_desc = f'"1.{desc_counter:04d} - MSSVR - {clean}"'
                pairs.append((k, new_desc))
                desc_counter += 1
            else:
                pairs.append((k, resolve_variables(v, variables)))

        rendered_blocks.append(pairs)
        all_keys.extend(k for k, _ in pairs)

    width = max(len(k) for k in all_keys) if all_keys else 0
    block_idx = 0

    for node in document:
        if node["type"] == "text":
            if not node["text"].lstrip().startswith("#"):
                output.append(resolve_variables(node["text"], variables))
        elif node["type"] == "report":
            output.append(f'<report type:"{node["report_type"]}">')
            desc = node["fields"].get("description", "").strip().strip('"').replace("CIS", "HTH")
            if desc:
                output.append(f'  description : "{desc}"')
            see_also = node["fields"].get("see_also", "")
            if see_also:
                output.append(f'  see_also    : "{SEE_ALSO_REPLACEMENT}"')
            output.append('</report>')
        elif node["type"] == "custom_item":
            output.append("<custom_item>")
            for k, v in rendered_blocks[block_idx]:
                output.append(f"  {k.ljust(width)} : {v}")
            output.append("</custom_item>")
            block_idx += 1

    return output, unknown_keys


def run_normalize(infile):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-normalized.audit")

    with open(infile, encoding="utf-8") as f:
        lines = f.readlines()

    variables = extract_variables(lines)
    document = parse_document(lines)
    output, unknown_keys = emit_normalize(document, variables)

    if unknown_keys:
        print("\nUnrecognized keys found — classify each:")
        reclassified = False
        for k in sorted(unknown_keys):
            while True:
                ans = input(f"  '{k}': (R)eal, (I)gnored, (S)kip? ").strip().upper()
                if ans in ('R', 'I', 'S'):
                    break
            if ans == 'R':
                REAL_KEYS.add(k)
                _persist_key(k, 'REAL_KEYS')
                reclassified = True
            elif ans == 'I':
                IGNORED_KEYS.add(k)
                _persist_key(k, 'IGNORED_KEYS')
                reclassified = True
        if reclassified:
            output, _ = emit_normalize(document, variables)

    item_count = sum(1 for line in output if line.strip() == '<custom_item>')

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(output) + "\n")

    print(f"\nNormalized audit written to:")
    print(f"  {outfile}")
    return outfile, item_count

# =============================================================================
# STEP 2 — CONVERT TO AUDIT_POWERSHELL
# =============================================================================

def parse_fields(block_text):
    fields = []
    for line in block_text.splitlines():
        stripped = line.strip()
        m = re.match(r'^(\w+)\s*:\s*(.*)$', stripped)
        if m:
            fields.append((m.group(1), m.group(2).strip()))
    return fields


def get_field(fields, name, default=""):
    for k, v in fields:
        if k == name:
            return v
    return default


def build_ps_registry(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs the raw value."""
    reg_key_raw  = get_field(fields, "reg_key")
    reg_item_raw = get_field(fields, "reg_item")
    value_type   = get_field(fields, "value_type", "POLICY_DWORD")
    value_data   = get_field(fields, "value_data", "")
    reg_option   = get_field(fields, "reg_option", "CAN_NOT_BE_NULL")
    check_type   = get_field(fields, "check_type", "")

    reg_item = unquote(reg_item_raw)
    ps_path  = reg_path(reg_key_raw)

    if reg_option == "MUST_NOT_EXIST" or unquote(value_data.strip()) == "<none>":
        ps = (
            f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
            f"if ($p -eq $null -or $p.PSObject.Properties['{reg_item}'] -eq $null) "
            f"{{ 'NOT_EXISTS' }} else {{ 'EXISTS' }}"
        )
        return ps, "POLICY_TEXT", '"NOT_EXISTS"', ""

    if value_type == "POLICY_DWORD":
        ps = (
            f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
            f"$val = if ($p -and $p.PSObject.Properties['{reg_item}'] -ne $null) "
            f"{{ [int]$p.'{reg_item}' }} else {{ $null }}; "
            f"if ($val -ne $null) {{ [string]$val }} else {{ 'NOT_FOUND' }}"
        )
        return ps, "POLICY_TEXT", value_data, check_type

    if value_type == "POLICY_SET":
        ps = (
            f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
            f"$v = if ($p -and $p.PSObject.Properties['{reg_item}'] -ne $null) "
            f"{{ [int]$p.'{reg_item}' }} else {{ $null }}; "
            f"if ($v -eq 1) {{ 'Enabled' }} elseif ($v -eq 0) {{ 'Disabled' }} else {{ 'NOT_FOUND' }}"
        )
        return ps, "POLICY_TEXT", value_data, check_type

    if value_type == "POLICY_MULTI_TEXT":
        ps = (
            f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
            f"$val = if ($p) {{ $p.'{reg_item}' }} else {{ @() }}; "
            f"if ($val) {{ ($val -join ',') }} else {{ '' }}"
        )
        vd_raw = unquote(value_data.strip())
        if "&&" in vd_raw:
            parts = sorted([unquote(p.strip()) for p in value_data.strip().split("&&")])
            out_vd = '"' + ",".join(parts) + '"'
        else:
            out_vd = value_data
        return ps, "POLICY_TEXT", out_vd, check_type

    # POLICY_TEXT (and anything else)
    ps = (
        f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
        f"$val = if ($p) {{ [string]$p.'{reg_item}' }} else {{ $null }}; "
        f"if ($val -ne $null) {{ $val }} else {{ 'NOT_FOUND' }}"
    )
    return ps, "POLICY_TEXT", value_data, check_type


def build_ps_reg_check(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs EXISTS/NOT_EXISTS."""
    value_data  = get_field(fields, "value_data")
    reg_option  = get_field(fields, "reg_option", "MUST_NOT_EXIST")
    key_item    = get_field(fields, "key_item", "")
    ps_key_path = reg_path(value_data)
    item        = unquote(key_item)

    def _exists_ps():
        if item:
            return (
                f"$p = Get-ItemProperty -Path '{ps_key_path}' -ErrorAction SilentlyContinue; "
                f"if ($p -ne $null -and $p.PSObject.Properties['{item}'] -ne $null) "
                f"{{ 'EXISTS' }} else {{ 'NOT_EXISTS' }}"
            )
        return f"if (Test-Path '{ps_key_path}') {{ 'EXISTS' }} else {{ 'NOT_EXISTS' }}"

    if reg_option == "MUST_NOT_EXIST":
        return _exists_ps(), "POLICY_TEXT", '"NOT_EXISTS"', ""
    elif reg_option == "CAN_BE_NULL":
        return _exists_ps(), "POLICY_TEXT", '"EXISTS || NOT_EXISTS"', ""
    else:
        return _exists_ps(), "POLICY_TEXT", '"EXISTS"', ""


def build_ps_lockout_policy(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs the raw secedit value."""
    lockout_policy = get_field(fields, "lockout_policy")
    value_data     = get_field(fields, "value_data", "0")
    sec_key        = LOCKOUT_SECEDIT.get(lockout_policy, lockout_policy)
    ps = (
        f"$tmp = [System.IO.Path]::GetTempFileName(); "
        f"secedit /export /cfg $tmp /quiet; "
        f"$val = (Get-Content $tmp | Where-Object {{ $_ -match '^{sec_key}\\s*=' }} | Select-Object -Last 1) -replace '.*=\\s*',''; "
        f"Remove-Item $tmp -Force; "
        f"if ($val -ne '') {{ $val.Trim() }} else {{ 'NOT_FOUND' }}"
    )
    return ps, "POLICY_TEXT", value_data, ""


def build_ps_password_policy(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs the raw secedit value."""
    password_policy = get_field(fields, "password_policy")
    value_type      = get_field(fields, "value_type", "POLICY_DWORD")
    value_data      = get_field(fields, "value_data", "0")
    sec_key         = PASSWORD_SECEDIT.get(password_policy, password_policy)
    ps_base = (
        f"$tmp = [System.IO.Path]::GetTempFileName(); "
        f"secedit /export /cfg $tmp /quiet; "
        f"$val = (Get-Content $tmp | Where-Object {{ $_ -match '^{sec_key}\\s*=' }} | Select-Object -Last 1) -replace '.*=\\s*',''; "
        f"Remove-Item $tmp -Force; "
    )
    if value_type == "POLICY_SET":
        ps = ps_base + "if ($val -eq '1') { 'Enabled' } elseif ($val -eq '0') { 'Disabled' } else { 'NOT_FOUND' }"
        return ps, "POLICY_TEXT", value_data, ""
    ps = ps_base + "if ($val -ne '') { $val.Trim() } else { 'NOT_FOUND' }"
    return ps, "POLICY_TEXT", value_data, ""


def build_ps_audit_policy(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs auditpol value string."""
    subcategory = get_field(fields, "audit_policy_subcategory")
    value_data  = get_field(fields, "value_data", "")
    subcat      = unquote(subcategory)
    subcat_esc  = subcat.replace("'", "\\'")

    def nessus_to_auditpol(v):
        v = v.strip()
        if v == "Success, Failure":
            return "Success and Failure"
        if v in ("Success", "Failure", "No Auditing"):
            return v
        return v

    if "||" in value_data:
        parts = [unquote(p.strip()) for p in value_data.split("||")]
        out_vd = '"' + " || ".join(nessus_to_auditpol(p) for p in parts) + '"'
    else:
        out_vd = '"' + nessus_to_auditpol(unquote(value_data)) + '"'

    ps = (
        f"$val = 'No Auditing'; "
        f"$r = auditpol /get /subcategory:'{subcat_esc}' 2>&1; "
        f"$line = $r | Where-Object {{ $_ -like '*{subcat_esc}*' }} | Select-Object -Last 1; "
        f"if ($line) {{ $parts = $line -split '\\s{{2,}}'; if ($parts.Count -gt 1) {{ $val = $parts[-1].Trim() }} }}; "
        f"$val"
    )
    return ps, "POLICY_TEXT", out_vd, ""


def build_ps_user_rights(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs sorted comma-joined members."""
    right_type = get_field(fields, "right_type")
    value_data = get_field(fields, "value_data", "")
    check_type = get_field(fields, "check_type", "")
    right = right_type.strip()
    ps_header = (
        f"$tmp = [System.IO.Path]::GetTempFileName(); "
        f"secedit /export /cfg $tmp /areas USER_RIGHTS /quiet; "
        f"$line = (Get-Content $tmp | Where-Object {{ $_ -match '^{right}\\s*=' }} | Select-Object -Last 1); "
        f"$members = if ($line) {{ ($line -replace '.*=\\s*','').Trim() -split ',' | ForEach-Object {{ $_.Trim() -replace '\\*','' }} | Sort-Object }} else {{ @() }}; "
        f"Remove-Item $tmp -Force; "
    )
    vd = value_data.strip()

    if check_type == "CHECK_SUPERSET":
        expected = [unquote(p.strip()) for p in vd.split("&&")] if "&&" in vd else [unquote(vd)]
        expected_ps = "@(" + ", ".join(f"'{v.replace(chr(39), chr(92)+chr(39))}'" for v in expected) + ")"
        ps = (
            ps_header +
            f"$expected = {expected_ps}; "
            f"$ok = $true; foreach ($e in $expected) {{ $found = $false; foreach ($m in $members) {{ if ($m -like $e) {{ $found = $true }} }}; if (-not $found) {{ $ok = $false }} }}; "
            f"if ($ok) {{ 'STATUS: PASSED' }} else {{ 'STATUS: FAILED' }}"
        )
        return ps, "POLICY_TEXT", '"STATUS: PASSED"', ""

    ps = ps_header + "if ($members.Count -gt 0) { ($members -join ',') } else { '' }"

    if vd == '""' or vd == "":
        return ps, "POLICY_TEXT", '""', ""

    if "&&" in vd and "||" not in vd:
        expected = sorted([unquote(p.strip()) for p in vd.split("&&")])
        out_vd = '"' + ",".join(expected) + '"'
        return ps, "POLICY_TEXT", out_vd, ""

    return ps, "POLICY_TEXT", value_data, ""


def build_ps_check_account(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs Enabled/Disabled or name."""
    account_type = get_field(fields, "account_type")
    value_data   = get_field(fields, "value_data", "Disabled")

    if account_type == "GUEST_ACCOUNT":
        ps = (
            "$u = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; "
            "if ($u -ne $null) { if ($u.Enabled) { 'Enabled' } else { 'Disabled' } } else { 'NOT_FOUND' }"
        )
        return ps, "POLICY_TEXT", value_data, ""

    elif account_type == "ADMINISTRATOR_ACCOUNT":
        ps = (
            "$a = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }; "
            "if ($a -ne $null) { $a.Name } else { 'NOT_FOUND' }"
        )
        return ps, "POLICY_TEXT", value_data, "CHECK_NOT_EQUAL"

    expected_raw = unquote(value_data)
    return f"# account_type: {account_type}; 'NOT_FOUND'", "POLICY_TEXT", '"NOT_FOUND"', ""


def build_ps_anonymous_sid(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs Enabled/Disabled."""
    value_data = get_field(fields, "value_data", "Disabled")
    ps = (
        "$p = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue; "
        "$v = if ($p) { [int]$p.AnonymousNameLookup } else { $null }; "
        "if ($v -eq 0) { 'Disabled' } elseif ($v -eq 1) { 'Enabled' } else { 'NOT_FOUND' }"
    )
    return ps, "POLICY_TEXT", value_data, ""


def build_ps_banner_check(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs actual banner text."""
    ps_path    = reg_path(get_field(fields, "reg_key"))
    reg_item   = unquote(get_field(fields, "reg_item"))
    value_data = get_field(fields, "value_data", "")
    expected   = unquote(value_data)
    ps = (
        f"$p = Get-ItemProperty -Path '{ps_path}' -ErrorAction SilentlyContinue; "
        f"if ($p) {{ [string]$p.'{reg_item}' }} else {{ 'NOT_FOUND' }}"
    )
    if expected == "":
        return ps, "POLICY_TEXT", '".+"', "CHECK_REGEX"
    return ps, "POLICY_TEXT", value_data, "CHECK_REGEX"


def build_ps_wmi_policy(fields):
    """Return (ps_args, value_type, value_data, check_type) — script outputs the raw WMI attribute value."""
    ns         = unquote(get_field(fields, "wmi_namespace", "root/CIMV2"))
    query      = unquote(get_field(fields, "wmi_request"))
    attr       = unquote(get_field(fields, "wmi_attribute"))
    value_data = get_field(fields, "value_data", "")
    ps = (
        f"$obj = Get-WmiObject -Namespace '{ns}' -Query '{query}' -ErrorAction SilentlyContinue; "
        f"$val = if ($obj) {{ $obj.{attr} }} else {{ $null }}; "
        f"if ($val -ne $null) {{ [string]$val }} else {{ 'NOT_FOUND' }}"
    )
    return ps, "POLICY_TEXT", value_data, ""


def sanitize_powershell_args(text):
    fixed_lines = []
    fix_count = 0
    for line in text.splitlines():
        original = line
        if re.match(r'\s*powershell_args\s*:', line):
            line = re.sub(r"'([^'\"]*)\"+(')", r"'\1\2", line)
            line = re.sub(r"('\")([ ^'\"]*')", r"'\2", line)
            m = re.match(r'^(\s*powershell_args\s*:\s*")(.+)("\s*)$', line)
            if m and '"' in m.group(2):
                line = m.group(1) + m.group(2).replace('"', "'") + m.group(3)
        elif re.match(r'\s*description\s*:', line):
            m = re.match(r'^(\s*description\s*:\s*")(.+)("\s*)$', line)
            if m and "'" in m.group(2):
                line = m.group(1) + m.group(2).replace("'", "") + m.group(3)
        if line != original:
            fix_count += 1
        fixed_lines.append(line)
    return "\n".join(fixed_lines), fix_count


def convert_custom_item(block_text):
    fields = parse_fields(block_text)
    item_type = get_field(fields, "type")

    if item_type == "AUDIT_POWERSHELL":
        return block_text

    description = get_field(fields, "description")
    info        = get_field(fields, "info")
    reference   = get_field(fields, "reference")
    see_also    = get_field(fields, "see_also")

    if item_type == "REGISTRY_SETTING":
        ps_args, out_vt, out_vd, out_ct = build_ps_registry(fields)
    elif item_type == "REG_CHECK":
        ps_args, out_vt, out_vd, out_ct = build_ps_reg_check(fields)
    elif item_type == "LOCKOUT_POLICY":
        ps_args, out_vt, out_vd, out_ct = build_ps_lockout_policy(fields)
    elif item_type == "PASSWORD_POLICY":
        ps_args, out_vt, out_vd, out_ct = build_ps_password_policy(fields)
    elif item_type == "AUDIT_POLICY_SUBCATEGORY":
        ps_args, out_vt, out_vd, out_ct = build_ps_audit_policy(fields)
    elif item_type == "USER_RIGHTS_POLICY":
        ps_args, out_vt, out_vd, out_ct = build_ps_user_rights(fields)
    elif item_type == "CHECK_ACCOUNT":
        ps_args, out_vt, out_vd, out_ct = build_ps_check_account(fields)
    elif item_type == "ANONYMOUS_SID_SETTING":
        ps_args, out_vt, out_vd, out_ct = build_ps_anonymous_sid(fields)
    elif item_type == "BANNER_CHECK":
        ps_args, out_vt, out_vd, out_ct = build_ps_banner_check(fields)
    elif item_type == "WMI_POLICY":
        ps_args, out_vt, out_vd, out_ct = build_ps_wmi_policy(fields)
    else:
        ps_args = f"# TODO: convert {item_type}; 'STATUS: MANUAL_REVIEW'"
        out_vt, out_vd, out_ct = "POLICY_TEXT", '"STATUS: MANUAL_REVIEW"', ""

    lines_out = ["<custom_item>"]

    def ef(key, val):
        lines_out.append(f"  {key} : {val}")

    ef("type", "AUDIT_POWERSHELL")
    if description:
        ef("description", description)
    if info:
        ef("info", info)
    if reference:
        ef("reference", reference)
    if see_also:
        ef("see_also", see_also)
    if out_ct:
        ef("check_type", out_ct)
    ef("value_type", out_vt)
    ef("value_data", out_vd)
    ef("powershell_args", f'"{ps_args}"')
    lines_out.append("</custom_item>")
    return "\n".join(lines_out)


# ---------- Converter state machine ----------

IF_OPEN      = re.compile(r'^\s*<if>')
IF_CLOSE     = re.compile(r'^\s*</if>')
COND_OPEN    = re.compile(r'^\s*<condition[^>]*>')
COND_CLOSE   = re.compile(r'^\s*</condition>')
THEN_OPEN    = re.compile(r'^\s*<then>')
THEN_CLOSE   = re.compile(r'^\s*</then>')
ELSE_OPEN    = re.compile(r'^\s*<else>')
ELSE_CLOSE   = re.compile(r'^\s*</else>')
ITEM_OPEN    = re.compile(r'^\s*<custom_item>')
ITEM_CLOSE   = re.compile(r'^\s*</custom_item>')
REPORT_OPEN  = re.compile(r'^\s*<report\b')
REPORT_CLOSE = re.compile(r'^\s*</report>')


class Converter:
    def __init__(self):
        self.output_lines = []
        self.current_line_index = -1
        self.first_if_index = None
        self.last_if_close_index = None
        self.outer_report_range = None
        self.if_nesting_level = 0
        self.collecting_item = False
        self.item_lines = []
        self.collecting_report = False
        self.report_lines = []
        self.current_report_start = None
        self.source_controls = 0
        self.total_controls = 0
        self.converted_controls = 0

    def process_content(self, content):
        self.all_lines = content.splitlines()
        self._identify_outer_if_block()
        if self.first_if_index is None or self.last_if_close_index is None:
            return content  # no <if> structure, pass through
        for line in self.all_lines:
            self._process_line(line)
        return "\n".join(self.output_lines)

    def _identify_outer_if_block(self):
        for i, line in enumerate(self.all_lines):
            if IF_OPEN.match(line):
                self.first_if_index = i
                break
        for i in range(len(self.all_lines) - 1, -1, -1):
            if IF_CLOSE.match(self.all_lines[i]):
                self.last_if_close_index = i
                break
        in_report = False
        report_start = None
        for i, line in enumerate(self.all_lines):
            if REPORT_OPEN.match(line):
                in_report = True
                report_start = i
            if in_report and REPORT_CLOSE.match(line):
                if (
                    self.first_if_index is not None
                    and self.last_if_close_index is not None
                    and self.first_if_index < report_start < self.last_if_close_index
                ):
                    self.outer_report_range = (report_start, i)
                in_report = False
                report_start = None

    def _emit(self, line):
        self.output_lines.append(line)

    def _process_line(self, line):
        self.current_line_index += 1
        line_no = self.current_line_index

        if IF_OPEN.match(line):
            self.if_nesting_level += 1
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if IF_CLOSE.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            self.if_nesting_level -= 1
            return
        if COND_OPEN.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if COND_CLOSE.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if THEN_OPEN.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if THEN_CLOSE.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if ELSE_OPEN.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return
        if ELSE_CLOSE.match(line):
            if self.if_nesting_level == 1:
                self._emit(line)
            return

        if ITEM_OPEN.match(line):
            self.collecting_item = True
            self.item_lines = [line]
            return
        if self.collecting_item:
            self.item_lines.append(line)
            if ITEM_CLOSE.match(line):
                self.collecting_item = False
                block = "\n".join(self.item_lines)
                self.source_controls += 1
                converted = convert_custom_item(block)
                self._emit(converted)
                self.total_controls += 1
                if get_field(parse_fields(block), "type") != "AUDIT_POWERSHELL":
                    self.converted_controls += 1
                self.item_lines = []
            return

        if REPORT_OPEN.match(line):
            self.collecting_report = True
            self.report_lines = [line]
            self.current_report_start = line_no
            return
        if self.collecting_report:
            self.report_lines.append(line)
            if REPORT_CLOSE.match(line):
                self.collecting_report = False
                if (
                    self.outer_report_range is not None
                    and self.current_report_start == self.outer_report_range[0]
                ):
                    self._emit("\n".join(self.report_lines))
                self.current_report_start = None
            return

        self._emit(line)


def run_convert(infile):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-converted.audit")

    with open(infile, encoding="utf-8") as f:
        content = f.read()

    conv = Converter()
    result = conv.process_content(content)
    result, fix_count = sanitize_powershell_args(result)

    result = normalize_custom_item_indent(result)
    result = re.sub(r'</custom_item>\s*\n(\s*<custom_item>)', r'</custom_item>\n\n\1', result)
    result_lines = align_colons(result.splitlines())
    result = '\n'.join(result_lines) + '\n'

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(result)

    print(f"\n✓ SUCCESS: Converted audit written to:")
    print(f"  {outfile}")
    if fix_count:
        print(f"  {fix_count} powershell_args line(s) sanitized")
    print(f"  Source controls : {conv.source_controls}")
    print(f"  Output controls : {conv.total_controls}")
    print(f"  Converted to PS : {conv.converted_controls}")
    return outfile

# =============================================================================
# STEP 3 — RENUMBER AUDIT DESCRIPTIONS
# =============================================================================

_AUDIT_DESC_RE = re.compile(r'"1\.\d{4} - MSSVR - ')


def run_renumber(infile):
    with open(infile, encoding='utf-8') as f:
        content = f.read()

    counter = 0

    def replacer(m):
        nonlocal counter
        counter += 1
        return f'"1.{counter:04d} - MSSVR - '

    content = _AUDIT_DESC_RE.sub(replacer, content)
    item_count = sum(1 for line in content.splitlines() if line.strip() == '<custom_item>')

    with open(infile, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n  Renumbered audits written to:")
    print(f"  {infile}")
    return item_count, counter

# =============================================================================
# MAIN
# =============================================================================

def main():
    infile = input("Enter path to input .audit file: ").strip().strip('"').strip("'")
    if not os.path.isfile(infile):
        print("ERROR: Input file does not exist.")
        return

    with open(infile, encoding='utf-8') as f:
        original_lines = f.readlines()
    original_item_count = sum(1 for line in original_lines if re.match(r'\s*<custom_item>', line))

    print("\n--- Step 1: Normalize ---")
    norm_file, norm_item_count = run_normalize(infile)

    print("\n--- Step 2: Convert ---")
    conv_file = run_convert(norm_file)

    print("\n--- Step 3: Renumber ---")
    final_item_count, desc_count = run_renumber(conv_file)

    print(f"\n{'='*50}")
    print(f"  Original  <custom_item> blocks : {original_item_count}")
    print(f"  Normalized <custom_item> blocks: {norm_item_count}")
    print(f"  Final     <custom_item> blocks : {final_item_count}")
    print(f"  Numbered descriptions          : {desc_count}")
    if final_item_count == original_item_count:
        print(f"  All {original_item_count} audits preserved.")
    else:
        diff = original_item_count - final_item_count
        print(f"  WARNING: {diff} audit(s) may have been lost.")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
