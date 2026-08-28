"""

****************** Should be ran on MICROSOFT WINDOWS ONLY ******************

This script is a Tenable/Nessus Audit-to-PowerShell conversion engine. Its purpose is to take traditional Windows .audit 
controls and transform them into a standardized AUDIT_POWERSHELL format that performs the compliance check using PowerShell 
commands instead of built-in audit types.

In practical terms, it's a migration tool that converts legacy audit checks such as:

                PASSWORD_POLICY
                LOCKOUT_POLICY
                REGISTRY_SETTING
                USER_RIGHTS_POLICY
                AUDIT_POLICY_SUBCATEGORY
                CHECK_ACCOUNT
                    into 
                type : AUDIT_POWERSHELL

        High-Level Workflow

Read a Windows .audit file.
Extract every <custom_item>.
Determine the audit control type.
Generate equivalent PowerShell code.
Replace the original control with an AUDIT_POWERSHELL control.
Write a new file ending in:.audit

                Original TypeConverted
                PASSWORD_POLICY
                LOCKOUT_POLICY
                REGISTRY_SETTING 
                REG_CHECK  
                USER_RIGHTS_POLICY  
                AUDIT_POLICY_SUBCATEGORY  
                ANONYMOUS_SID_SETTING  
                BANNER_CHECK  
                CHECK_ACCOUNT  

"""

import os
import re
from collections import Counter

# ============================================================
# HELPERS
# ============================================================

def parse_block(block):

    fields = {}

    for line in block.splitlines():

        m = re.match(
            r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)",
            line
        )

        if m:
            fields[m.group(1).lower()] = m.group(2).strip()

    return fields


def get_field(fields, key, default=""):
    return fields.get(key.lower(), default)

def clean(value):
    if not value:
        return value
    return value.strip().strip('"').strip("'")


def clean_description(value):
    if not value:
        return value

    value = value.strip().replace('"', '').replace("'", "")
    value = re.sub(r"^\s*\d+\.\d+\s*-\s*[^-]+?\s*-\s*", "", value)
    return value.strip()


def build_powershell_item(
    description,
    info,
    reference,
    see_also,
    value_data,
    powershell_args,
    check_type="CHECK_REGEX"
):
    description = clean_description(description)
    # print("POWERSHELL_ARGS =", ps)
    # print("BUILD_POWERSHELL_ITEM CALLED")

    return f"""<custom_item>
  type                     : AUDIT_POWERSHELL
  description              : {description}
  info                     : {info}
  reference                : {reference}
  see_also                 : {see_also}
  value_type               : POLICY_TEXT
  value_data               : {value_data}
  powershell_args          : "{powershell_args}"
  check_type               : {check_type}
</custom_item>"""

# ============================================================
# PASSWORD POLICY
# ============================================================

def convert_password_policy(fields):

    policy = get_field(fields, "password_policy")

    mapping = {

        "ENFORCE_PASSWORD_HISTORY": (
            '"24"',
            r"$line = net accounts | Where-Object { $_ -match 'password history' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "MAXIMUM_PASSWORD_AGE": (
            '"365"',
            r"$line = net accounts | Where-Object { $_ -match 'Maximum password age' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "MINIMUM_PASSWORD_AGE": (
            '"1"',
            r"$line = net accounts | Where-Object { $_ -match 'Minimum password age' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "MINIMUM_PASSWORD_LENGTH": (
            '"14"',
            r"$line = net accounts | Where-Object { $_ -match 'Minimum password length' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "COMPLEXITY_REQUIREMENTS": (
            '"1"',
            r"$tmp = Join-Path $env:TEMP 'secpol.inf'; "
            r"secedit.exe /export /cfg $tmp 2>$null | Out-Null; "
            r"(Select-String -Path $tmp -Pattern '^PasswordComplexity\s*=\s*(\d+)').Matches.Groups[1].Value"
        ),

        "REVERSIBLE_ENCRYPTION": (
            '"0"',
            r"$tmp = Join-Path $env:TEMP 'secpol.inf'; "
            r"secedit.exe /export /cfg $tmp 2>$null | Out-Null; "
            r"(Select-String -Path $tmp -Pattern '^ClearTextPassword\s*=\s*(\d+)').Matches.Groups[1].Value"
        ),

        "RELAX_MINIMUM_PASSWORD_LENGTH_LIMITS": (
            '"1"',
            r"$line = net accounts | Where-Object { $_ -match 'Minimum password length' }; "
            r"if ($line -match '(\d+)$') { "
            r"if ([int]$matches[1] -gt 14) { '1' } else { '0' } "
            r"} else { 'NOT_FOUND' }"
        ),

        "LOCKOUT_ADMINS": (
            '"1"',
            r"$line = net accounts | Where-Object { $_ -match 'Lockout threshold' }; "
            r"if ($line -match '(\d+)$') { "
            r"if ([int]$matches[1] -gt 0) { '1' } else { '0' } "
            r"} else { 'NOT_FOUND' }"
        ),
        
        "FORCE_LOGOFF": (
            '"Never"',
            r"$line = net accounts | Where-Object { $_ -match 'Force user logoff' }; "
            r"if ($line -match ':\s*(.+)$') { $matches[1].Trim() } else { 'NOT_FOUND' }"
        ),

    }

    if policy not in mapping:
        return None

    expected, ps = mapping[policy]

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        expected,
        ps,
    )

# ============================================================
# LOCKOUT POLICY
# ============================================================

def convert_lockout_policy(fields):

    policy = get_field(fields, "lockout_policy")

    mapping = {

        "LOCKOUT_THRESHOLD": (
            '"5"',
            "$line = net accounts | Where-Object "
            "{ $_ -match 'Lockout threshold' }; "
            "if ($line -match '(\\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "LOCKOUT_DURATION": (
            '"15"',
            r"$line = net accounts | Where-Object { $_ -match 'Lockout duration' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),

        "LOCKOUT_RESET": (
            '"15"',
            r"$line = net accounts | Where-Object { $_ -match 'Lockout observation window' }; "
            r"if ($line -match '(\d+)$') { $matches[1] } else { 'NOT_FOUND' }"
        ),
    }

    if policy not in mapping:
        return None

    expected, ps = mapping[policy]

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        expected,
        ps,
    )


# ============================================================
# REGISTRY SETTING
# ============================================================

def convert_registry_setting(fields):

    reg_key = clean(get_field(fields, "reg_key"))
    reg_item = clean(get_field(fields, "reg_item"))
    reg_include_hku_users = clean(get_field(fields, "reg_include_hku_users"))

    if not reg_key or not reg_item:
        return None

    # Special case: Relax minimum password length limits
    if reg_item == "RelaxMinimumPasswordLengthLimits":

        ps = (
            "$line = net accounts | Where-Object "
            "{ $_ -match 'Minimum password length' }; "
            "if ($line -match '(\\d+)$') { "
            "if ([int]$matches[1] -gt 14) { '1' } else { '0' } "
            "} else { 'NOT_FOUND' }"
        )

        return build_powershell_item(
            get_field(fields, "description"),
            get_field(fields, "info"),
            get_field(fields, "reference"),
            get_field(fields, "see_also"),
            get_field(fields, "value_data"),
            ps,
        )


    # HKU SID-based checks
    if reg_key.startswith("HKU\\") and reg_include_hku_users:

        subkey = reg_key[4:]  # remove HKU\


        # ps = (
        #     f"$result = Get-ChildItem Registry::HKEY_USERS | "
        #     f"Where-Object {{ $_.PSChildName -like '{reg_include_hku_users}' }} | "
        #     f"ForEach-Object {{ "
        #     f"$path = Join-Path $_.PSPath '{subkey}'; "
        #     f"if (Test-Path $path) {{ "
        #     f"try {{ "
        #     f"Get-ItemPropertyValue -Path $path -Name '{reg_item}' -ErrorAction Stop "
        #     f"}} catch {{}} "
        #     f"}} "
        #     f"}} | Select-Object -First 1; "
        #     f"if ($null -eq $result) {{ 'NOT_FOUND' }} else {{ $result }}"
            
        # )

        ps = (
            f"$matches = Get-ChildItem Registry::HKEY_USERS | "
            f"Where-Object {{ $_.PSChildName -like '{reg_include_hku_users}' }}; "

            f"if (-not $matches) {{ "
            f"'NO_MATCHING_SIDS' "
            f"}} else {{ "

            f"$results = $matches | ForEach-Object {{ "

            f"$path = Join-Path $_.PSPath '{subkey}'; "

            f"if (Test-Path $path) {{ "

            f"try {{ "
            f"Get-ItemPropertyValue "
            f"-Path $path "
            f"-Name '{reg_item}' "
            f"-ErrorAction Stop "
            f"}} catch {{}} "

            f"}} "

            f"}}; "

            f"if ($results) {{ "
            f"$results | Select-Object -First 1 "
            f"}} else {{ "
            f"'VALUE_NOT_FOUND_IN_ANY_PROFILE' "
            f"}} "
            f"}}"
        )


    else:

        ps_path = reg_key

        ps_path = ps_path.replace("HKLM\\", "HKLM:\\")
        ps_path = ps_path.replace("HKU\\", "Registry::HKEY_USERS\\")
        ps_path = ps_path.replace("HKCU\\", "HKCU:\\")
        ps_path = ps_path.replace("HKCR\\", "HKCR:\\")

        ps = (
            f"$path = '{ps_path}'; "
            f"$name = '{reg_item}'; "
            f"if (-not (Test-Path $path)) "
            f"{{ 'PATH_NOT_FOUND: ' + $path }} "
            f"else {{ "
            f"try {{ "
            f"$props = Get-ItemProperty -Path $path -ErrorAction Stop; "
            f"if ($name -in $props.PSObject.Properties.Name) "
            f"{{ $props.$name }} "
            f"else {{ 'VALUE_NOT_FOUND: ' + $name }} "
            f"}} catch {{ 'ERROR: ' + $_.Exception.Message }} "
            f"}}"
        )

    #print(repr(ps))

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        get_field(fields, "value_data"),
        ps,
    )
# ============================================================
# REG_CHECK
# ============================================================

def convert_reg_check(fields):


    reg_key = clean(get_field(fields, "value_data")).strip('"')
    key_item = clean(get_field(fields, "key_item")).strip('"')

    reg_include_hku_users = clean(get_field(fields, "reg_include_hku_users"))

    if not reg_key or not key_item:
        return None


    if reg_key.startswith("HKU\\") and reg_include_hku_users:

        subkey = reg_key[4:]

        # ps = (
        #     f"$result = Get-ChildItem Registry::HKEY_USERS | "
        #     f"Where-Object {{ $_.PSChildName -like '{reg_include_hku_users}' }} | "
        #     f"ForEach-Object {{ "
        #     f"$path = Join-Path $_.PSPath '{subkey}'; "
        #     f"if (Test-Path $path) {{ "
        #     f"try {{ "
        #     f"Get-ItemPropertyValue -Path $path -Name '{key_item}' -ErrorAction Stop "
        #     f"}} catch {{}} "
        #     f"}} "
        #     f"}} | Select-Object -First 1; "
        #     f"if ($null -eq $result) {{ 'NOT_FOUND' }} else {{ $result }}"
        # )

        ps = (
            f"$matches = Get-ChildItem Registry::HKEY_USERS | "
            f"Where-Object {{ $_.PSChildName -like '{reg_include_hku_users}' }}; "

            f"if (-not $matches) {{ "
            f"'NO_MATCHING_SIDS' "
            f"}} else {{ "

            f"$results = $matches | ForEach-Object {{ "

            f"$path = Join-Path $_.PSPath '{subkey}'; "

            f"if (Test-Path $path) {{ "

            f"try {{ "
            f"Get-ItemPropertyValue "
            f"-Path $path "
            f"-Name '{key_item}' "
            f"-ErrorAction Stop "
            f"}} catch {{}} "

            f"}} "

            f"}}; "

            f"if ($results) {{ "
            f"$results | Select-Object -First 1 "
            f"}} else {{ "
            f"'VALUE_NOT_FOUND_IN_ANY_PROFILE' "
            f"}} "
            f"}}"
        )

    else:

        ps_path = reg_key

        ps_path = ps_path.replace("HKLM\\", "HKLM:\\")
        ps_path = ps_path.replace("HKU\\", "Registry::HKEY_USERS\\")
        ps_path = ps_path.replace("HKCU\\", "HKCU:\\")
        ps_path = ps_path.replace("HKCR\\", "HKCR:\\")


        ps = (
            f"try {{ "
            f"(Get-ItemProperty "
            f"-Path '{ps_path}' "
            f"-ErrorAction Stop).{key_item} "
            f"}} catch {{ 'NOT_FOUND' }}"
        )

        # print("REG_CHECK:", repr(ps))

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        get_field(fields, "value_data"),
        ps,
    )

# ============================================================
# USER RIGHTS POLICY
# ============================================================

def convert_user_rights_policy(fields):

    right = get_field(fields, "right_type")

    if not right:
        return None

    ps = (
        "$tmp = Join-Path $env:TEMP 'secpol.inf'; "
        "secedit.exe /export /cfg $tmp 2>$null | Out-Null; "
        f"if (Test-Path $tmp) "
        f"{{ (Select-String -Path $tmp -Pattern '^{right}\\s*=').Line }} "
        f"else {{ 'NOT_FOUND' }}"
    )

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        get_field(fields, "value_data"),
        ps,
    )

# ============================================================
# AUDIT POLICY SUBCATEGORY
# ============================================================


def convert_audit_policy(fields):

    subcat = clean(get_field(fields, "audit_policy_subcategory"))

    if not subcat:
        return None

    ps = (
        f"try {{ "
        f"$text = (auditpol.exe /get /subcategory:'{subcat}' 2>$null | Out-String); "
        f"if ($text -match '(No Auditing|Success and Failure|Success|Failure)') "
        f"{{ $matches[1] }} else {{ 'NOT_FOUND' }} "
        f"}} catch {{ 'NOT_FOUND' }}"
    )

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        get_field(fields, "value_data"),
        ps,
    )


# ============================================================
# ANONYMOUS_SID_SETTING
# ============================================================

def convert_anonymous_sid_setting(fields):

    # print("ANONYMOUS SID CONTROL")
    # print(fields)

    ps = (
        "(Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa')."
        "TurnOffAnonymousBlock"
    )

    result = build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        '"Disabled"',
        ps,
    )

    # print("RESULT =", repr(result))

    return result
# ============================================================
# BANNER_CHECK
# ============================================================
def convert_banner_check(fields):
    # print("BANNER_CHECK CONVERTER CALLED")
    reg_key = get_field(fields, "reg_key").strip('"')
    reg_item = get_field(fields, "reg_item").strip('"')


    if not reg_key or not reg_item:
        return None

    ps_path = reg_key.replace(
        "HKLM\\",
        "HKLM:\\"
    )

    ps = (
        f"try {{ "
        f"(Get-ItemProperty -Path '{ps_path}' -ErrorAction Stop).{reg_item} "
        f"}} catch {{ 'NOT_FOUND' }}"
    )

    # print("REG_KEY =", repr(reg_key))
    # print("REG_ITEM =", repr(reg_item))

    return build_powershell_item(
        get_field(fields, "description"),
        get_field(fields, "info"),
        get_field(fields, "reference"),
        get_field(fields, "see_also"),
        get_field(fields, "value_data"),
        ps,
        get_field(fields, "check_type", "CHECK_REGEX")
    )

# ============================================================
# CHECK_ACCOUNT
# ============================================================

def convert_check_account(fields):
    # print("CHECK_ACCOUNT CONVERTER CALLED")

    account_type = get_field(fields, "account_type")

    if account_type == "GUEST_ACCOUNT":

        ps = (
            "(Get-LocalUser | "
            "Where-Object {$_.SID.Value -match '-501$'}).Name"
        )

        if get_field(fields, "value_type") == "POLICY_SET":

            ps = (
                "(Get-LocalUser | "
                "Where-Object {$_.SID.Value -match '-501$'}).Enabled"
            )

        return build_powershell_item(
            get_field(fields, "description"),
            get_field(fields, "info"),
            get_field(fields, "reference"),
            get_field(fields, "see_also"),
            get_field(fields, "value_data"),
            ps,
            get_field(fields, "check_type", "CHECK_REGEX")
        )

    if account_type == "ADMINISTRATOR_ACCOUNT":

        ps = (
            "(Get-LocalUser | "
            "Where-Object {$_.SID.Value -match '-500$'}).Name"
        )

        return build_powershell_item(
            get_field(fields, "description"),
            get_field(fields, "info"),
            get_field(fields, "reference"),
            get_field(fields, "see_also"),
            get_field(fields, "value_data"),
            ps,
            get_field(fields, "check_type", "CHECK_REGEX")
        )

    account_type = get_field(fields, "account_type")

    # # # print("ACCOUNT_TYPE RAW =", repr(account_type))

    # # # if account_type == "GUEST_ACCOUNT":

    # # #     print("MATCHED GUEST_ACCOUNT")

    # # # if account_type == "ADMINISTRATOR_ACCOUNT":

    # # #     print("MATCHED ADMINISTRATOR_ACCOUNT")

    return None

# ============================================================
# CONVERSION ENGINE
# ============================================================

def convert_block(block):

    converted = None

    fields = parse_block(block)
    item_type = get_field(fields, "type")

    #
    # Already PowerShell
    #
    if item_type == "AUDIT_POWERSHELL":
        return block

    #
    # Password Policy
    #
    if item_type == "PASSWORD_POLICY":

        converted = convert_password_policy(fields)

        if converted:
            return converted

    #
    # Lockout Policy
    #
    if item_type == "LOCKOUT_POLICY":

        converted = convert_lockout_policy(fields)

        if converted:
            return converted

    #
    # Registry
    #
    if item_type == "REGISTRY_SETTING":

        converted = convert_registry_setting(fields)

        if converted:
            return converted

    #
    # REG_CHECK
    #
    if item_type == "REG_CHECK":

        converted = convert_reg_check(fields)

        if converted:
            return converted

    #
    # User Rights Policy
    #
    if item_type == "USER_RIGHTS_POLICY":

        converted = convert_user_rights_policy(fields)

        if converted:
            return converted

    #
    # Audit Policy
    #

    if item_type == "AUDIT_POLICY_SUBCATEGORY":
        converted = convert_audit_policy(fields)
        if converted:

            # print("\nCONVERTING AUDIT POLICY")
            # print(converted[:300])

            return converted
        
    #
    # Anonymous SID Setting
    #
    elif item_type == "ANONYMOUS_SID_SETTING":

        converted = convert_anonymous_sid_setting(fields)

        # print("ANON RETURN =", converted is not None)

        if converted is not None:
            return converted

    #
    # Banner Check
    #
    if item_type == "BANNER_CHECK":

        converted = convert_banner_check(fields)

        if converted:
            return converted

    # 
    # CHECK_ACCOUNT
    # 
    if item_type == "CHECK_ACCOUNT":

        converted = convert_check_account(fields)

        if converted:
            return converted
    
    #
    # Unsupported
    #
    
    if item_type == "PASSWORD_POLICY":

        print(
            "\nUNMAPPED PASSWORD POLICY:",
            get_field(fields, "password_policy")
        )


    if converted is not None:
        return converted

    return block



# ============================================================
# EXTRACT CUSTOM ITEMS
# ============================================================

def process_file(infile):

    type_counter = Counter()

    outfile = os.path.join(
        os.path.dirname(infile),
        os.path.splitext(os.path.basename(infile))[0]
        + "-powershell.audit"
    )

    with open(infile, encoding="utf-8") as f:
        text = f.read()

    print(f"File size: {len(text)}")

    print(
        "custom_item count:",
        len(
            re.findall(
                r"<custom_item>",
                text,
                flags=re.IGNORECASE
            )
        )
    )

    matches = re.findall(
        r"<custom_item>.*?</custom_item>",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    print("regex matches:", len(matches))

    pattern = r"<custom_item>.*?</custom_item>"

    total_controls = 0
    converted_count = 0
    remaining_types = Counter()


    test_type_counter = Counter()

    def detect_test_type(powershell_args):
        args = (powershell_args or "").lower()
        if not args:
            return "unknown"
        if "get-itemproperty" in args or "get-itempropertyvalue" in args or "registry::" in args or "hklm:\\" in args or "hkcu:\\" in args or "hkcr:\\" in args or "hkey_users" in args:
            return "powershell / registry"
        if "get-wmiobject" in args or "get-ciminstance" in args or "wmi" in args or "win32_" in args:
            return "powershell / wmi"
        if "auditpol.exe" in args or "auditpol" in args:
            return "powershell / auditpol"
        if "net accounts" in args or "password history" in args or "lockout threshold" in args or "lockout duration" in args or "force user logoff" in args:
            return "powershell / net accounts"
        if "secedit.exe" in args or "secpol.inf" in args:
            return "powershell / secedit"
        if "get-localuser" in args or "sid.value" in args:
            return "powershell / localuser"
        return "powershell / other"

    def replace_item(match):

        nonlocal total_controls
        nonlocal converted_count

        total_controls += 1

        block = match.group(0)

        fields = parse_block(block)
        item_type = fields.get("type", "UNKNOWN")

        type_counter[item_type] += 1
        
        new_block = convert_block(block)

        DEBUG = False

        ...

        if DEBUG and new_block:
            fields = parse_block(new_block)

            ps = fields.get("powershell_args")

            if ps:
                print(ps)

        if new_block is None:

            print("\nCONVERTER RETURNED NONE")
            print("TYPE:", item_type)

            remaining_types["NONE_RETURNED"] += 1

            return block

        if new_block != block:

            converted_count += 1
            #print("CONVERTED:", item_type)

        new_fields = parse_block(new_block)
        test_type = detect_test_type(new_fields.get("powershell_args"))
        test_type_counter[test_type] += 1

        new_type = new_fields.get("type", "UNKNOWN")

        if new_type != "AUDIT_POWERSHELL":
            remaining_types[new_type] += 1

        if new_block == block:
            #print("UNCHANGED:", item_type)
            if item_type != "AUDIT_POWERSHELL":
                remaining_types[item_type] += 1

        return new_block

    output = re.sub(
        pattern,
        replace_item,
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(output)

    with open(outfile, "r", encoding="utf-8") as f:
        verify = f.read()

    print("\nVERIFICATION")
    print("AUDIT_POWERSHELL:", verify.count("AUDIT_POWERSHELL"))
    print("AUDIT_POLICY_SUBCATEGORY:", verify.count("AUDIT_POLICY_SUBCATEGORY"))

    print("\nRemaining Output Types:")

    for t, c in sorted(remaining_types.items()):
        print(f"  {t}: {c}")



    
    existing_powershell = type_counter.get("AUDIT_POWERSHELL", 0)

    unchanged_controls = (
        total_controls
        - converted_count
        - existing_powershell
    )

    print()
    print(f"Total controls     : {total_controls}")
    print(f"Converted controls : {converted_count}")
    print(f"Existing PowerShell: {existing_powershell}")
    print(f"Unchanged controls : {unchanged_controls}")

    print(f"Conversion rate    : "
        f"{round((converted_count / total_controls) * 100, 1)}%"
        if total_controls else "0%")

    print("\nControl Types Found:")

    for t, c in sorted(type_counter.items()):
        print(f"  {t}: {c}")

    print("\nTest Types Found:")
    for t, c in sorted(test_type_counter.items()):
        print(f"  {t}: {c}")

    print("\nOUTPUT COUNTS")

    print(
        "AUDIT_POWERSHELL:",
        output.count("AUDIT_POWERSHELL")
    )

    print(
        "AUDIT_POLICY_SUBCATEGORY:",
        output.count("AUDIT_POLICY_SUBCATEGORY")
    )

    print(
        "USER_RIGHTS_POLICY:",
        output.count("USER_RIGHTS_POLICY")
    )

    print(
        "auditpol:",
        output.count("auditpol")
    )

    print(f"Output file        : {outfile}")


    # with open(outfile, "r", encoding="utf-8") as f:
    #     verify = f.read()

    # for bad in [
    #     "Get-ItemProperty-Path",
    #     "-Path$path",
    #     "-ErrorActionStop",
    #     "Get-ItemProperty '\"HKLM:",
    # ]:
    #     if bad in verify:
    #         print("FOUND:", bad)

# ============================================================
# MAIN
# ============================================================

def main():

    infile = input(
        "Enter Windows .audit file: "
    ).strip().strip('"').strip("'")

    if not os.path.isfile(infile):
        print("File not found.")
        return

    process_file(infile)


if __name__ == "__main__":
    main()