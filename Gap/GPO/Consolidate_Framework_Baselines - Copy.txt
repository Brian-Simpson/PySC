import argparse
import json
import os
import re
import warnings
from pathlib import Path
import pandas as pd
from openpyxl.utils import get_column_letter
from openpyxl.styles import PatternFill, Font, Alignment
from openpyxl.formatting.rule import CellIsRule


# Suppress openpyxl user warnings about header formatting constraints
warnings.simplefilter(action='ignore', category=UserWarning)

BASE_DIR = Path(r"C:\PySC")
FRAMEWORK_LIBRARY_PATH = BASE_DIR / "Framework_Library.xlsx"
POTENTIAL_AUDIT_PATH = BASE_DIR / "Master_Baselines.xlsx"
ACTUAL_AUDIT_DIR = BASE_DIR / "actual_audit_inputs"
FINAL_OUTPUT_PATH = BASE_DIR / "Unified_Compliance_Matrix.xlsx"

# Mapping dictionary: PowerShell description patterns → canonical control identifiers
PS_DESCRIPTION_TO_CONTROL = {
    "Length of password history": "ENFORCE_PASSWORD_HISTORY",
    "Maximum password age": "MAXIMUMPASSWORDAGE",
    "Minimum password age": "MINIMUMPASSWORDAGE",
    "Minimum password length": "MINIMUMPASSWORDLENGTH",
    "Password must meet complexity": "PASSWORDCOMPLEXITY",
    "Store passwords using reversible encryption": "CLEARTEXTPASSWORD",
    "Clear Text Password": "CLEARTEXTPASSWORD",
    "Account lockout duration": "LOCKOUTDURATION",
    "Account lockout threshold": "LOCKOUTTHRESHOLD",
    "Account lockout counter": "LOCKOUTCOUNTER",
    "Reset account lockout": "RESETLOCKOUTCOUNT",
    "Credential Validation": "AUDITCREDENTIALVALIDATION",
    "Application Group Management": "AUDITAPPLICATIONGROUPMANAGEMENT",
    "Security Group Management": "AUDITSECURITYGROUPMANAGEMENT",
    "User Account Management": "AUDITUSRACCOUNTMANAGEMENT",
    "Plug and Play Events": "AUDITPNPACTIVITY",
    "Process Creation": "AUDITPROCESSCREATION",
    "Group Membership": "AUDITGROUPMEMBERSHIP",
    "Detailed File Share": "AUDITDETAILEDFILESHARE",
    "File Share": "AUDITFILESHARE",
    "Other Object Access Events": "AUDITOTHEROBJECTACCESS",
    "Removable Storage": "AUDITREMOVABLESTORAGE",
    "Interactive logon": "INTERACTIVELOGON",
    "Logon Banner": "LOGONBANNER",
    "Account Policy": "ACCOUNTPOLICY",
    "Relax minimum password length": "RELAXMINIMUMPASSWORDLENGTH",
}

# Mapping for auditpol subcategories: subcategory name → control identifier
AUDITPOL_SUBCATEGORY_MAP = {
    "Logoff": "AUDITLOGOFF",
    "Logon": "AUDITLOGON",
    "Account Lockout": "AUDITACCOUNTLOCKOUT",
    "Credential Validation": "AUDITCREDENTIALVALIDATION",
    "Application Group Management": "AUDITAPPLICATIONGROUPMANAGEMENT",
    "Security Group Management": "AUDITSECURITYGROUPMANAGEMENT",
    "User Account Management": "AUDITUSRACCOUNTMANAGEMENT",
    "Plug and Play Events": "AUDITPNPACTIVITY",
    "Process Creation": "AUDITPROCESSCREATION",
    "Group Membership": "AUDITGROUPMEMBERSHIP",
    "Detailed File Share": "AUDITDETAILEDFILESHARE",
    "File Share": "AUDITFILESHARE",
    "Other Object Access Events": "AUDITOTHEROBJECTACCESS",
    "Removable Storage": "AUDITREMOVABLESTORAGE",
    "Other Logon/Logoff Events": "AUDIOTOTHERLOGON",
    "Special Logon": "AUDITSPECIALLOGON",
    "Kerberos Authentication Service": "AUDITKERBEROS",
    "Kerberos Service Ticket Operations": "AUDITKERBEROSSERVICETICKET",
    "Other Account Logon Events": "AUDITOTHERACCOUNT",
    "Directory Service Changes": "AUDITDIRECTORYSERVICECHANGES",
    "Directory Service Replication": "AUDITDIRECTORYSERVICEREPLICATION",
    "Detailed Directory Service Replication": "AUDITDETAILEDDIRECTORYSERVICEREPLICATION",
    "Directory Service Access": "AUDITDIRECTORYSERVICEACCESS",
}
def extract_nist_id(val):
    """Isolates and standardizes control tokens (e.g. '800-53|AC-2' -> 'AC-2')."""
    if pd.isna(val):
        return ""
    val_str = str(val).strip().upper()
    match = re.search(r"([A-Z]{2,3}-\d{1,2})", val_str)
    if match:
        control = match.group(1)
        prefix, num_part = control.split("-")
        return f"{prefix}-{int(num_part)}"
    return val_str

def extract_control_key(row):
    """Extracts a stable audit control key from row metadata.

    Priority order:
    1. Explicit policy fields (password_policy, lockout_policy, etc.)
    2. Policy descriptions from PowerShell Where-Object filters mapped to canonical control IDs
    3. Policy names extracted from PowerShell arguments (MinimumPasswordAge, EnforcePasswordHistory, etc.)
    4. Registry/WMI identifiers (reg_item, reg_key, wmi_attribute, etc.)
    5. Normalized description text
    """
    global GLOBAL_PROPERTY_COUNTS

    # 1. Check explicit policy fields first
    for col in ["password_policy", "lockout_policy", "reg_item", "reg_key", "wmi_attribute", "wmi_key", "key_item"]:
        if col in row and pd.notna(row[col]) and str(row[col]).strip() != "":
            return str(row[col]).strip().upper()

    # 2. Check PowerShell args for descriptive patterns that map to control IDs
    ps_args_raw = row.get("powershell_args", "")
    if pd.isna(ps_args_raw):
        ps_args = ""
    else:
        ps_args = str(ps_args_raw).strip()
    
    if ps_args:
        # First, try to match known PowerShell description patterns (e.g., "Length of password history")
        for desc_pattern, control_id in PS_DESCRIPTION_TO_CONTROL.items():
            if desc_pattern.lower() in ps_args.lower():
                return control_id

        # 2.5 Extract auditpol subcategory values (e.g., /subcategory:'Logoff' → AUDITLOGOFF)
        auditpol_pattern = r"/subcategory\s*:\s*['\"]([^'\"]+)['\"]"
        match = re.search(auditpol_pattern, ps_args, re.IGNORECASE)
        if match:
            subcategory_name = match.group(1).strip()
            if subcategory_name in AUDITPOL_SUBCATEGORY_MAP:
                return AUDITPOL_SUBCATEGORY_MAP[subcategory_name]
            if subcategory_name and len(subcategory_name) > 2:
                return f"AUDIT{subcategory_name.upper().replace(' ', '').replace('/', '')}"

        # 2.5.9 DECISIVE QUOTE-ISOLATED REGISTRY PARAMETER CHECK (Updated for HKLM:\ and object dot-properties)
        if any(k in ps_args.upper() for k in ("REGISTRY::", "GET-ITEMPROPERTY", "HKLM:", "HKCU:")):
            # 1. Extract the true target property name using your safe quote-isolated regex
            prop_name = None
            prop_matches = re.findall(r"['\.\[]([A-Za-z0-9_-]+)['\]]?", ps_args)
            
            for candidate in prop_matches:
                candidate_up = candidate.upper()
                if candidate_up not in ("PSOBJECT", "PROPERTIES", "GET-ITEMPROPERTY", "PATH", "ERRORACTION", "SILENTLYCONTINUE", "REGISTRY", "HKEY_LOCAL_MACHINE", "HKLM", "HKCU", "VAL", "RAW", "TRUE", "FALSE", "NULL", "WRITE-HOST", "IF", "ELSE", "NOUTPUT"):
                    prop_name = candidate
                    break

            # 2. Isolate the path by checking for standard -Path quotes or provider paths like HKLM:\...
            path_part_raw = ""
            path_quote_match = re.search(r"-Path\s+['\"]([^'\"]+)['\"]", ps_args, re.IGNORECASE)
            if path_quote_match:
                path_part_raw = path_quote_match.group(1).strip()
            else:
                # Catch short-hand providers like 'HKLM:\Software\...' or 'HKCU:\Software\...'
                provider_match = re.search(r"['\"](HK[LM|CU]:\\[^'\"]+)['\"]", ps_args, re.IGNORECASE)
                if provider_match:
                    path_part_raw = provider_match.group(1).strip()
                else:
                    fallback_match = re.search(r"['\"](Registry::[^'\"]+)['\"]", ps_args, re.IGNORECASE)
                    if fallback_match:
                        path_part_raw = fallback_match.group(1).strip()

            if path_part_raw and prop_name:
                # Clean up path slashes and strip structural prefixes out
                raw_path = path_part_raw.replace("/", "\\")
                raw_path = re.sub(r"(?i)^(Registry\s*::\s*|HKLM:\\|HKCU:\\)", "", raw_path).strip("\\ ")
                path_parts = [p for p in raw_path.split("\\") if p]
                
                p_key = prop_name.upper()
                
                # Check duplication status using our lookahead tracker mapping
                if p_key not in GLOBAL_PROPERTY_COUNTS:
                    GLOBAL_PROPERTY_COUNTS[p_key] = {"paths": {raw_path.upper()}, "is_duplicate": False}
                else:
                    if raw_path.upper() not in GLOBAL_PROPERTY_COUNTS[p_key]["paths"]:
                        GLOBAL_PROPERTY_COUNTS[p_key]["paths"].add(raw_path.upper())
                        GLOBAL_PROPERTY_COUNTS[p_key]["is_duplicate"] = True

                # Dynamic Output Router: Prepend folder prefixes ONLY if the property name has duplicates
                if GLOBAL_PROPERTY_COUNTS[p_key]["is_duplicate"] and len(path_parts) >= 2:
                    folder_prefix = f"{path_parts[-2]}_{path_parts[-1]}"
                    return f"'{folder_prefix} {prop_name}'"
                elif GLOBAL_PROPERTY_COUNTS[p_key]["is_duplicate"] and len(path_parts) == 1:
                    return f"'{path_parts[-1]} {prop_name}'"
                
                # Standard clean assignment format for completely unique properties
                return f"'{prop_name}'"
            
            elif prop_name:
                return f"'{prop_name}'"
        # 2.6 REVISED: Explicit capture for Windows Secedit User Rights Assignments
        if "/areas USER_RIGHTS" in ps_args or "/quiet" in ps_args:
            priv_match = re.search(r"\b(Se[A-Za-z]+(?:Privilege|Right))\b", ps_args, re.IGNORECASE)
            if priv_match and priv_match.group(1).upper() != "NTACCOUNT":
                return f"USER_RIGHTS {priv_match.group(1)}"

        # 2.7 User rights and secedit-derived checks (SeDebugPrivilege, SeRemoteShutdownPrivilege, ...)
        sec_match = re.search(r"\b(Se[A-Za-z]+Privilege)\b", ps_args, re.IGNORECASE)
        if sec_match:
            return f"USER_RIGHT_{sec_match.group(1).upper()}"

        # 2.8 Service existence / status checks
        svc_match = re.search(r"Get-Service\s+-Name\s+['\"]?([A-Za-z0-9\*_\-]+)['\"]?", ps_args, re.IGNORECASE)
        if svc_match:
            return f"SERVICE_{svc_match.group(1).upper().replace('*','PFX') }"

        cim_svc = re.search(r"Get-CimInstance\s+Win32_Service\s*.*Name\s*-eq\s*'([^']+)'", ps_args, re.IGNORECASE)
        if cim_svc:
            return f"SERVICE_{cim_svc.group(1).upper()}"

        # 2.9 Optional Windows features
        opt_match = re.search(r"-FeatureName\s+['\"]?([A-Za-z0-9_\-]+)['\"]?", ps_args, re.IGNORECASE)
        if opt_match:
            return f"OPTIONAL_FEATURE_{opt_match.group(1).upper()}"

        # 2.10 Local user / SID shorthand checks (map common well-known RIDs)
        if re.search(r"-Match '\\-500\$'|-Match '\\-501\$'", ps_args, re.IGNORECASE):
            if re.search(r"-500\$", ps_args):
                return "LOCAL_USER_BUILTIN_ADMINISTRATOR"
            if re.search(r"-501\$", ps_args):
                return "LOCAL_USER_GUEST"

        # 2.11 net accounts textual checks for password policy
        if re.search(r"net\s+accounts", ps_args, re.IGNORECASE):
            if re.search(r"password history", ps_args, re.IGNORECASE):
                return "ENFORCE_PASSWORD_HISTORY"
            if re.search(r"Maximum password", ps_args, re.IGNORECASE) or re.search(r"maximum password", ps_args, re.IGNORECASE):
                return "MAXIMUMPASSWORDAGE"
            if re.search(r"password length", ps_args, re.IGNORECASE):
                return "MINIMUMPASSWORDLENGTH"
            if re.search(r"lockout", ps_args, re.IGNORECASE):
                return "ACCOUNT_LOCKOUT_POLICY"

    # 3. Extract policy names from PowerShell arguments
    if ps_args:
        policy_patterns = [
            r"(?:Get-ItemProperty|Where-Object|match).*?([A-Za-z]*(?:Password|Lockout|Account|LogonBanner|UserRights)[A-Za-z]*)",
            r"'([A-Za-z]*(?:Password|Lockout|Account|LogonBanner|UserRights)[A-Za-z]*)'",
            r"\"([A-Za-z]*(?:Password|Lockout|Account|LogonBanner|UserRights)[A-Za-z]*)\"",
            r"-Name\s+['\"]?([A-Za-z]*(?:Password|Lockout|Account|LogonBanner|UserRights)[A-Za-z]*)",
        ]
        for pattern in policy_patterns:
            match = re.search(pattern, ps_args, re.IGNORECASE)
            if match:
                policy_name = match.group(1).strip()
                if policy_name and len(policy_name) > 2 and policy_name.upper() != "NTACCOUNT":
                    return policy_name.upper()

    # 4. Fall back to registry/WMI keys if present
    for col in ["reg_item", "reg_key", "wmi_attribute", "wmi_key", "key_item"]:
        if col in row and pd.notna(row[col]) and str(row[col]).strip() != "":
            return str(row[col]).strip().upper()

    # 4.1 PRIORITIZED: Intercept SQL baseline markers BEFORE checking text metadata columns
    sql_val = row.get("sql_expect", "")
    src_val = str(row.get("Source_File", "")).upper()
    
    if (pd.notna(sql_val) and str(sql_val).strip() != "") or "SQL" in src_val:
        sval = str(sql_val) if pd.notna(sql_val) else ""
        if re.search(r"xp_cmdshell", sval, re.IGNORECASE):
            return "SQL_XP_CMDSHELL"
        if re.search(r"audit level", sval, re.IGNORECASE):
            return "SQL_AUDIT_LEVEL"
        return "SQL_BASELINE_CHECK"

    # 4.2 Generic text fallback column processing (Completely safe from SQL rows)
    val_data = row.get("value_data", "")
    if pd.notna(val_data) and str(val_data).strip() != "":
        norm = re.sub(r"[^A-Z0-9]", "", str(val_data).upper())
        if norm:
            return f"VALUE_{norm[:40]}"

    info_val = row.get("info", "")
    if pd.notna(info_val) and str(info_val).strip() != "":
        norm2 = re.sub(r"[^A-Z0-9]", "", str(info_val).upper())
        if norm2:
            return f"INFO_{norm2[:40]}"

    # 5. Fall back to normalized description
    description = str(row.get("description", "")).strip()
    if description:
        norm_desc = re.sub(r"[^A-Z0-9 ]", "", description.upper())
        norm_desc = re.sub(r"\s+", " ", norm_desc).strip()
        return norm_desc[:120]

    # Final platform-derived fallback using source file hints
    src = row.get("Source_File", "")
    if pd.notna(src) and str(src).strip() != "":
        src_up = str(src).upper()
        if "SQL" in src_up:
            return "SQL_BASELINE_CHECK"
        if "WINDOWS_11" in src_up or "WINDOWS11" in src_up or "MSWRK" in src_up:
            return "WINDOWS_11_GENERIC_CHECK"
        if "WINDOWS" in src_up or "SERVER" in src_up:
            return "WINDOWS_SERVER_GENERIC_CHECK"
        if "AWS" in src_up:
            return "AWS_BASELINE_CHECK"
        if "AZURE" in src_up:
            return "AZURE_BASELINE_CHECK"

    return "UNKNOWN_CONTROL"


def parse_powershell_target_object(ps_args_str):
    """Scans PowerShell argument strings to parse the core target configuration object."""
    if not ps_args_str or pd.isna(ps_args_str):
        return ""
    args_upper = str(ps_args_str).strip().upper()
    
    # NEW: Prioritized Registry Target Filtering (Corrected to filter script syntax words)
    if "REGISTRY::" in args_upper or "GET-ITEMPROPERTY" in args_upper:
        prop_matches = re.findall(r"(?:PROPERTIES\s*\[\s*['\"]|['\.]\s*['\"]?)([A-Z0-9_-]+)(?:['\"]?\s*\]|['\"]?)", args_upper)
        candidate_prop = None
        for candidate in prop_matches:
            if candidate not in ("PSOBJECT", "PROPERTIES", "GET-ITEMPROPERTY", "PATH", "ERRORACTION", "SILENTLYCONTINUE", "REGISTRY", "HKEY_LOCAL_MACHINE", "HKLM", "VAL", "RAW", "TRUE", "FALSE", "NULL"):
                candidate_prop = candidate
                break

        if candidate_prop:
            path_match = re.search(r"-PATH\s+['\"]([^'\"]+)['\"]", args_upper)
            if path_match:
                raw_path = path_match.group(1).replace("/", "\\").strip("'\"\\ ")
                path_parts = [p for p in raw_path.split("\\") if p]
                if len(path_parts) >= 2:
                    return f"REG_PROP:{path_parts[-2]}_{path_parts[-1]}_{candidate_prop}"
            return f"REG_PROP:{candidate_prop}"


    # NEW: Secure capture for secedit USER_RIGHTS checks to prevent degradation to generic text tokens
    if "/AREAS USER_RIGHTS" in args_upper or "USER_RIGHTS" in args_upper:
        priv_match = re.search(r"\b(SE[A-Za-z]+(?:PRIVILEGE|RIGHT))\b", args_upper, re.IGNORECASE)
        if priv_match and priv_match.group(1).upper() != "NTACCOUNT":
            return f"USER_RIGHT:{priv_match.group(1).upper()}"


    reg_match = re.search(r"(HKLM:\\|HKCU:\\|SOFTWARE\\[A-Z0-9_\\]+)", args_upper)
    if reg_match:
        path_snippet = reg_match.group(1)
        item_match = re.search(r"-NAME\s+[\"']?([A-Z0-9_-]+)[\"']?", args_upper)
        if item_match:
            return f"REG:{path_snippet}\\{item_match.group(1)}"
        return f"REG:{path_snippet}"
        
    policy_match = re.search(r"([A-Z][A-Za-z0-9_]{6,}(?:HISTORY|AGE|LENGTH|LOGON|RIGHT|LOCKOUT))", args_upper)
    if policy_match:
        return f"POLICY:{policy_match.group(1)}"
        
    clean_args = re.sub(r"GET-ITEMPROPERTY|GET-ITEM|SELECT-OBJECT|WHERE-OBJECT|-PATH|-NAME", "", args_upper)
    words = [w for w in re.findall(r"([A-Z0-9_-]{4,})", clean_args) if w not in ["TRUE", "FALSE", "NULL"]]
    if words:
        return f"PS_TOKEN:{words}"
    return ""


def build_composite_technical_key(row):
    """Constructs a robust unique multidimensional settings signature key."""
    target_object = ""
    if "powershell_args" in row and pd.notna(row["powershell_args"]) and str(row["powershell_args"]).strip() != "":
        target_object = parse_powershell_target_object(row["powershell_args"])
        
    if not target_object:
        for col in ["reg_key", "reg_item", "password_policy", "lockout_policy", "wmi_key", "wmi_attribute", "key_item"]:
            if col in row and pd.notna(row[col]) and str(row[col]).strip() != "":
                target_object += f"|{str(row[col]).strip().upper()}"
                
    subcategory = ""
    for col in ["audit_policy_subcategory", "account_type", "right_type", "check_type"]:
        if col in row and pd.notna(row[col]) and str(row[col]).strip() != "":
            subcategory += f"|{str(row[col]).strip().upper()}"

    ref_val = row.get("reference", "")
    norm_nist = extract_nist_id(ref_val)
    family_layer = norm_nist.split("-")[0] if "-" in norm_nist else ""

    raw_key = f"FAM:{family_layer}|OBJ:{target_object}{subcategory}"
    return re.sub(r"\|+", "|", raw_key).strip().upper()


def parse_raw_audit_to_dataframe(file_path: Path):
    """Parses a single Nessus .audit file line-by-line into a structured DataFrame."""
    rows = []
    block_start = re.compile(r"^\s*<(custom_item|item)>", re.IGNORECASE)
    block_end = re.compile(r"^\s*</(custom_item|item)>", re.IGNORECASE)
    comment_start = re.compile(r"^\s*#\s*<(custom_item|item)>", re.IGNORECASE)
    comment_end = re.compile(r"^\s*#\s*</(custom_item|item)>", re.IGNORECASE)
    attr_pattern = re.compile(r"^\s*#?\s*([a-zA-Z0-9_]+)\s*:\s*(.*)$")


    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        in_block = False
        is_commented_block = False
        current_item = {}

        for line in lines:
            if block_start.match(line):
                in_block = True
                is_commented_block = False
                current_item = {"Line_Status": "Active", "Source_File": file_path.name}
                continue
            if comment_start.match(line):
                in_block = True
                is_commented_block = True
                current_item = {"Line_Status": "Commented Out", "Source_File": file_path.name}
                continue

            if (is_commented_block and comment_end.match(line)) or (not is_commented_block and block_end.match(line)):
                if current_item:
                    rows.append(current_item)
                in_block = False
                current_item = {}
                continue

            if in_block:
                match = attr_pattern.match(line)
                if match:
                    key = match.group(1).lower().strip()
                    val = match.group(2).strip().replace('"', '')
                    current_item[key] = val

    except Exception as e:
        print(f"   [Error] Failed to ingest source layout file {file_path.name}: {e}")

    return pd.DataFrame(rows)


def format_dashboard_sheet(writer, sheet_name):
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.utils import get_column_letter

    def format_dashboard_sheet(writer, sheet_name):
        ws = writer.sheets[sheet_name]

        # HEADER STYLE
        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)

        # ✅ CORRECT VERSION (THIS IS THE FIX)
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")

        # Freeze top row
        ws.freeze_panes = "A2"

        # Enable filters
        ws.auto_filter.ref = ws.dimensions

        # ALIGNMENT
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical="top")

        # FIND STATUS COLUMN
        status_col = None
        for col_idx, cell in enumerate(ws[1], start=1):
            if cell.value == "Status":
                status_col = col_idx
                break

        # CONDITIONAL FORMATTING
        if status_col:
            col_letter = get_column_letter(status_col)

            ws.conditional_formatting.add(
                f"{col_letter}2:{col_letter}{ws.max_row}",
                CellIsRule(operator="equal", formula=['"Compliant"'],
                        fill=PatternFill(start_color="C6EFCE", fill_type="solid"))
            )
            ws.conditional_formatting.add(
                f"{col_letter}2:{col_letter}{ws.max_row}",
                CellIsRule(operator="equal", formula=['"Partial"'],
                        fill=PatternFill(start_color="FFEB9C", fill_type="solid"))
            )
            ws.conditional_formatting.add(
                f"{col_letter}2:{col_letter}{ws.max_row}",
                CellIsRule(operator="equal", formula=['"High Gap"'],
                        fill=PatternFill(start_color="F4CCCC", fill_type="solid"))
            )

        # ZEBRA STRIPING
        alt_fill = PatternFill(start_color="F9F9F9", fill_type="solid")
        for row_idx in range(2, ws.max_row + 1):
            if row_idx % 2 == 0:
                for col_idx in range(1, ws.max_column + 1):
                    ws.cell(row=row_idx, column=col_idx).fill = alt_fill

        # FORMAT PERCENT COLUMN
        for col_idx, cell in enumerate(ws[1], start=1):
            if cell.value == "Compliance %":
                for row_idx in range(2, ws.max_row + 1):
                    ws.cell(row=row_idx, column=col_idx).number_format = "0.00%"

        # BOLD FAMILY TOTAL ROWS
        for row in ws.iter_rows(min_row=2):
            if str(row[1].value) == str(row[0].value):
                for cell in row:
                    cell.font = Font(bold=True)

    """Dynamically scales Excel column widths based on cell string lengths."""
    ws = writer.sheets[sheet_name]
    for col_idx in range(1, ws.max_column + 1):
        max_len = 0
        col_letter = get_column_letter(col_idx)
        for row_idx in range(1, ws.max_row + 1):
            cell_value = ws.cell(row=row_idx, column=col_idx).value
            if cell_value is not None:
                max_len = max(max_len, len(str(cell_value)))
        final_width = min(max(max_len + 3, 11), 65)
        ws.column_dimensions[col_letter].width = final_width

from openpyxl.utils import get_column_letter

def autofit_excel_columns(writer, sheet_name):
    ws = writer.sheets[sheet_name]

    for col_idx in range(1, ws.max_column + 1):
        max_len = 0
        col_letter = get_column_letter(col_idx)

        for row_idx in range(1, ws.max_row + 1):
            cell_value = ws.cell(row=row_idx, column=col_idx).value
            if cell_value is not None:
                max_len = max(max_len, len(str(cell_value)))

        adjusted_width = min(max(max_len + 3, 11), 65)
        ws.column_dimensions[col_letter].width = adjusted_width

def format_scorecard_sheet(writer, sheet_name):
    ws = writer.sheets[sheet_name]

    header_fill = PatternFill(start_color="1F4E78", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)

    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font

    ws.column_dimensions["A"].width = 35
    ws.column_dimensions["B"].width = 20

def format_heatmap_sheet(writer, sheet_name):
    ws = writer.sheets[sheet_name]

    for col_idx, cell in enumerate(ws[1], start=1):
        if cell.value == "Compliance %":
            target_col = col_idx
            break

    # Apply gradient manually
    for row_idx in range(2, ws.max_row + 1):
        cell = ws.cell(row=row_idx, column=target_col)
        val = cell.value

        if val is None:
            continue

        if val >= 90:
            color = "63BE7B"  # green
        elif val >= 60:
            color = "FFEB84"  # yellow
        else:
            color = "F8696B"  # red

        cell.fill = PatternFill(start_color=color, fill_type="solid")

def build_unified_compliance_matrix():
    print("\n=======================================================")
    print("      RE-ARCHITECTING RELATIONAL COMPLIANCE PIPELINE   ")
    print("=======================================================")

    if not FRAMEWORK_LIBRARY_PATH.exists() or not POTENTIAL_AUDIT_PATH.exists():
        print("CRITICAL ERROR: Missing baseline script prerequisites inside C:\\PySC.")
        return

    # 1. Ingest corporate frameworks library matrix
    print("1. Ingesting static framework library mappings matrix...")
    df_frameworks = pd.read_excel(FRAMEWORK_LIBRARY_PATH, sheet_name="Master_Control_Library")
    framework_nist_col = next((c for c in df_frameworks.columns if "CONTROL" in c.upper() or "NIST" in c.upper()), None)
    if not framework_nist_col:
        print("CRITICAL ERROR: No valid NIST column mapped in Framework_Library.xlsx")
        return
    df_frameworks["Join_Anchor"] = df_frameworks[framework_nist_col].apply(extract_nist_id)

    print("[DEBUG] Unique Framework Anchors:", len(df_frameworks["Join_Anchor"].unique()))
    print("[DEBUG] Sample Framework Anchors:",
        df_frameworks["Join_Anchor"].dropna().unique()[:10])


    # 2. Map production files into a DataFrame and extract active parameters
    print("2. Ingesting and processing PowerShell parameters from company rules...")
    actual_data_by_platform = {}
    active_signatures_set = set()
    commented_counts_by_platform = {}
    
    # NEW: Global tracking dictionary to pre-calculate property counts across your entire pipeline
    global GLOBAL_PROPERTY_COUNTS
    GLOBAL_PROPERTY_COUNTS = {}
    
    # Global pool used specifically for the backwards-mapping framework check sheet
    global_active_company_controls = []


    for audit_file in ACTUAL_AUDIT_DIR.glob("*.audit"):
        fn = audit_file.name.upper()
        platform_key = "Unknown_Platform"
        if "AMAZON" in fn or "AWS" in fn: platform_key = "AWS_Foundations"
        elif "AZURE" in fn: platform_key = "Azure_Foundations"
        elif "NX-OS" in fn or "NXOS" in fn: platform_key = "Cisco_NXOS"
        elif "IOS" in fn: platform_key = "Cisco_IOS"
        elif "SQL" in fn: platform_key = "MS_SQL_Server"
        elif "WINDOWS_11" in fn or "WINDOWS11" in fn or "WIN_11" in fn or "MSWRK" in fn: 
            platform_key = "Windows_11_Enterprise"
        elif "WINDOWS_SERVER" in fn or "SERVER" in fn: 
            platform_key = "Windows_Server"

        df_raw = parse_raw_audit_to_dataframe(audit_file)
        if not df_raw.empty:
            # PRE-SCAN FOR REGISTRY DUPLICATES BEFORE NAMING ELEVATIONS BEGIN
            for _, r in df_raw.iterrows():
                args = str(r.get("powershell_args", ""))
                args_up = args.upper()
                if "REGISTRY::" in args_up or "GET-ITEMPROPERTY" in args_up:
                    # Using your refined, safe property extraction regex
                    p_match = re.findall(r"['\.\[]([A-Za-z0-9_-]+)['\]]", args)                  
                    p_name = None
                    for candidate in p_match:
                        if candidate.upper() not in ("PSOBJECT", "PROPERTIES", "GET-ITEMPROPERTY", "PATH", "ERRORACTION", "SILENTLYCONTINUE", "REGISTRY", "HKEY_LOCAL_MACHINE", "HKLM", "VAL", "RAW", "TRUE", "FALSE", "NULL"):
                            p_name = candidate.upper()
                            break
                            
                    path_part_raw = ""
                    path_quote_match = re.search(r"-Path\s+['\"]([^'\"]+)['\"]", args, re.IGNORECASE)
                    if path_quote_match:
                        path_part_raw = path_quote_match.group(1).strip()
                    else:
                        fallback_match = re.search(r"['\"](Registry::[^'\"]+)['\"]", args, re.IGNORECASE)
                        if fallback_match:
                            path_part_raw = fallback_match.group(1).strip()

                    if path_part_raw and p_name:
                        r_path = path_part_raw.replace("/", "\\")
                        r_path = re.sub(r"(?i)^Registry\s*::\s*", "", r_path).strip("\\ ").upper()
                        if p_name not in GLOBAL_PROPERTY_COUNTS:
                            GLOBAL_PROPERTY_COUNTS[p_name] = {"paths": {r_path}, "is_duplicate": False}
                        else:
                            if r_path not in GLOBAL_PROPERTY_COUNTS[p_name]["paths"]:
                                GLOBAL_PROPERTY_COUNTS[p_name]["paths"].add(r_path)
                                GLOBAL_PROPERTY_COUNTS[p_name]["is_duplicate"] = True

            # Calculate control keys and signatures using the pre-scanned lookahead values
            df_raw["Control_Key"] = df_raw.apply(extract_control_key, axis=1)
            df_raw["Technical_Signature"] = df_raw.apply(build_composite_technical_key, axis=1)
            
            # Map clean normalized joining keys for reverse lookups
            if "reference" in df_raw.columns:
                def safe_extract_anchor(row):
                    ref = row.get("reference", "")
                    anchor = extract_nist_id(ref)

                    if anchor:
                        return anchor

                    # ✅ FALLBACK: derive from Control_Key
                    ctrl = str(row.get("Control_Key", "")).upper()

                    # Example mappings (expand as needed)
                    if "PASSWORD" in ctrl:
                        return "IA-5"
                    if "LOCKOUT" in ctrl:
                        return "AC-7"
                    if "AUDIT" in ctrl:
                        return "AU-2"
                    if "ACCOUNT" in ctrl:
                        return "AC-2"

                    return ""  # still unmapped

                df_raw["Join_Anchor"] = df_raw.apply(safe_extract_anchor, axis=1)

                # DEBUG: Check actual mapping quality
                valid_actual = df_raw[df_raw["Join_Anchor"].str.strip() != ""]
                invalid_actual = df_raw[df_raw["Join_Anchor"].str.strip() == ""]

                print(f"[DEBUG] {platform_key} Valid Anchors:", len(valid_actual))
                print(f"[DEBUG] {platform_key} Missing Anchors:", len(invalid_actual))
            else:
                df_raw["Join_Anchor"] = ""

            active_mask = df_raw["Line_Status"] == "Active"
            
            # Append rows to the global reverse engineering matrix lookup pool
            df_active_only = df_raw[active_mask].copy()
            if not df_active_only.empty:
                df_active_only["Asset_Platform_Group"] = platform_key
                global_active_company_controls.append(df_active_only)

            for sig in df_raw[active_mask]["Technical_Signature"].unique():
                if sig and "OBJ:" in sig:
                    active_signatures_set.add(sig)

            comment_mask = df_raw["Line_Status"] == "Commented Out"
            commented_counts_by_platform[platform_key] = commented_counts_by_platform.get(platform_key, 0) + len(df_raw[comment_mask])

            if platform_key in actual_data_by_platform:
                actual_data_by_platform[platform_key] = pd.concat([actual_data_by_platform[platform_key], df_raw], ignore_index=True)
            else:
                actual_data_by_platform[platform_key] = df_raw

    # Combine all active production lines into an interactive unified tracking master pool
    df_all_active_company_rules = pd.concat(global_active_company_controls, ignore_index=True) if global_active_company_controls else pd.DataFrame()

    # 3. Read total potential baseline sheets loop
    xls_potential = pd.ExcelFile(POTENTIAL_AUDIT_PATH)
    
    # INITIALIZE TRACKING ARRAYS (Add reverse_gap_rows here)
    dashboard_summary = []
    gap_analysis_rows = []
    reverse_gap_rows = []  

    # NEW: Global tracking structures to build the framework metric block
    all_compiled_potential_anchors = []
    all_compiled_active_anchors = []
    with pd.ExcelWriter(FINAL_OUTPUT_PATH, engine="openpyxl") as writer:

        for sheet_name in xls_potential.sheet_names:
            platform_name = sheet_name.replace("_Baselines", "")
            print(f" -> Mapping relational signatures for platform: '{platform_name}'")
            
            df_potential = pd.read_excel(xls_potential, sheet_name=sheet_name)
            if "reference" not in df_potential.columns:
                continue

            df_potential["Control_Key"] = df_potential.apply(extract_control_key, axis=1)
            # Build signatures for default CIS potential controls
            df_potential["Technical_Signature"] = df_potential.apply(build_composite_technical_key, axis=1)

            # Match company PowerShell controls to the standard CIS potential control rows
            df_potential["Control_Scope"] = df_potential["Technical_Signature"].apply(
                lambda sig: "Actual Control" if sig in active_signatures_set and "|OBJ:" in sig else "Potential Control"
            )

            # Left join framework metadata columns side-by-side using NIST control identifiers
            df_potential["Join_Anchor"] = df_potential["reference"].apply(extract_nist_id)
            df_unified = pd.merge(
                df_potential, 
                df_frameworks.drop(columns=[framework_nist_col], errors='ignore'),
                on="Join_Anchor", 
                how="left"
            )
            # NEW: Collect data points for the framework-level matrix summary
            if "Join_Anchor" in df_unified.columns:
                # Isolate rows that possess valid NIST framework assignments
                valid_anchors = df_unified[df_unified["Join_Anchor"].str.strip() != ""].copy()
                if not valid_anchors.empty:
                    all_compiled_potential_anchors.append(valid_anchors["Join_Anchor"])
                    
                    # Also collect rows that are actively enforced in company configurations
                    # ✅ BEST PRACTICE: Count actuals directly from raw audit data
                    if "Join_Anchor" in df_raw.columns:
                        valid_actuals = df_raw[df_raw["Join_Anchor"].str.strip() != ""]
                        if not valid_actuals.empty:
                            all_compiled_active_anchors.append(valid_actuals["Join_Anchor"])

                print("DEBUG Active Anchors Sample:",
                    list(pd.concat(all_compiled_active_anchors).head(10)))

            # Track down true compliance framework gaps on your active controls
            gaps_mask = df_unified["Join_Anchor"].isna() | (df_unified["Join_Anchor"] == "")
            if framework_nist_col in df_unified.columns:
                gaps_mask = gaps_mask | df_unified[framework_nist_col].isna()
            
            df_gaps = df_unified[gaps_mask & (df_unified["Control_Scope"] == "Actual Control")].copy()
            if not df_gaps.empty:
                df_gaps["Platform_Source"] = platform_name
                gap_analysis_rows.append(df_gaps[["Platform_Source", "Original_File", "description", "reference"]])

            # NEW LOGIC: Trace backward tracking maps to establish COMPREHENSIVE mapping framework side-by-side
            df_actual_pool = actual_data_by_platform.get(platform_name, pd.DataFrame())
            if not df_actual_pool.empty:
                active_corp_rows = df_actual_pool[df_actual_pool["Line_Status"] == "Active"]
                for _, corp_row in active_corp_rows.iterrows():
                    corp_ref = str(corp_row.get("reference", "")).strip()
                    norm_corp_ref = extract_nist_id(corp_ref)
                    
                    # Pull matching columns from the Framework Library if they exist
                    fw_match_rows = df_frameworks[df_frameworks["Join_Anchor"] == norm_corp_ref]
                    
                    # Create dictionary of the corporate rule data
                    row_data = {
                        "Control_Key": corp_row.get("Control_Key", "UNKNOWN_CONTROL"),
                        "Reference_ID_Anchor": norm_corp_ref,
                        "Raw_Reference_String": corp_ref,
                        "Corporate_Audit_File": platform_name, # Pinpoints matching system platform
                        "Control_Description": corp_row.get("description", "N/A"),
                        "Item_Type": corp_row.get("block_type", "custom_item"),
                        "PowerShell_Args": corp_row.get("powershell_args", "N/A")
                    }
                    
                    # If we found a framework match in script 1, append its full framework rows side-by-side!
                    if not fw_match_rows.empty:
                        fw_row = fw_match_rows.iloc[0]
                        for col in df_frameworks.columns:
                            if col != "Join_Anchor":
                                row_data[f"Library_{col}"] = fw_row[col]
                    else:
                        # Mark explicitly as an unmapped gap if no library record exists
                        for col in df_frameworks.columns:
                            if col != "Join_Anchor":
                                row_data[f"Library_{col}"] = "[UNMAPPED GAP]"

                    reverse_gap_rows.append(row_data)

            # Process summary dashboard metrics calculations
            total_potential_rules = len(df_unified)
            actual_enforced = len(df_unified[df_unified["Control_Scope"] == "Actual Control"])
            mapped_rules = len(df_unified[(df_unified["Control_Scope"] == "Actual Control") & (~gaps_mask)])
            
            unutilized_cis_rules = total_potential_rules - actual_enforced
            commented_count = commented_counts_by_platform.get(platform_name, 0)
            currently_omitted_total = unutilized_cis_rules + commented_count

            dashboard_summary.append({
                "Platform Profile": platform_name,
                "Total Potential System Rules (CIS)": total_potential_rules,
                "Actual Enforced Rules (Company Active)": actual_enforced,
                "Enforced Rules Mapped to Framework": mapped_rules,
                "Framework Coverage Gaps Found": len(df_gaps),
                "Currently Omitted Rules (Total)": currently_omitted_total,
                " -> [Breakdown] Commented Out in File": commented_count,
                "Omitted CIS Rules": unutilized_cis_rules
            })

            # Clean and write the unified data sheets
            if "Join_Anchor" in df_unified.columns: 
                df_unified.drop(columns=["Join_Anchor"], inplace=True)
            if "Technical_Signature" in df_unified.columns: 
                df_unified.drop(columns=["Technical_Signature"], inplace=True)
                
            clean_tab_name = f"{platform_name}_Unified"[:31]
            df_unified.to_excel(writer, sheet_name=clean_tab_name, index=False)
            writer.sheets[clean_tab_name].sheet_properties.tabColor = "27AE60"
            autofit_excel_columns(writer, clean_tab_name)

            # Write out the raw company actual baseline data as a dedicated tab
            if not df_actual_pool.empty:
                raw_tab_name = f"Raw_Company_{platform_name}"[:31]
                cols_to_drop = ["Technical_Signature", "Join_Anchor", "Original_File_Source", "original_file"]
                df_write_raw = df_actual_pool.copy()
                for c in cols_to_drop:
                    if c in df_write_raw.columns:
                        df_write_raw.drop(columns=[c], inplace=True)
                
                # Reorder columns to place Control_Key prominently at the front
                front_cols = ["Control_Key", "description", "reference", "block_type", "powershell_args"]
                available_front = [c for c in front_cols if c in df_write_raw.columns]
                other_cols = sorted([c for c in df_write_raw.columns if c not in front_cols])
                df_write_raw = df_write_raw[available_front + other_cols]
                        
                df_write_raw.to_excel(writer, sheet_name=raw_tab_name, index=False)
                writer.sheets[raw_tab_name].sheet_properties.tabColor = "7F8C8D"
                autofit_excel_columns(writer, raw_tab_name)

        # Add a dedicated sheet for active corporate control keys and NIST mapping anchors
        if not df_all_active_company_rules.empty:
            df_control_keys = df_all_active_company_rules[
                [col for col in ["Asset_Platform_Group", "Control_Key", "reference", "Join_Anchor", "description", "block_type"] if col in df_all_active_company_rules.columns]
            ].copy()
            df_control_keys.to_excel(writer, sheet_name="Control_Key_Mapping", index=False)
            writer.sheets["Control_Key_Mapping"].sheet_properties.tabColor = "8E44AD"
            autofit_excel_columns(writer, "Control_Key_Mapping")

        # 4. Generate the Filtered Forward Gap Analysis Tab
        print("\n3. Compiling forward framework coverage gap analysis matrix...")
        if gap_analysis_rows:
            df_all_gaps = pd.concat(gap_analysis_rows, ignore_index=True)
        else:
            df_all_gaps = pd.DataFrame(columns=["Platform_Source", "Original_File", "description", "reference"])
            
        df_all_gaps.to_excel(writer, sheet_name="Enforced_Framework_Gaps", index=False)
        writer.sheets["Enforced_Framework_Gaps"].sheet_properties.tabColor = "C0392B"
        autofit_excel_columns(writer, "Enforced_Framework_Gaps")

        # 5. Generate the Comprehensive Comprehensive Mapping Trace Sheet (Orange Tab)
        print("4. Structuring Comprehensive Production Reference Mapping matrix tab...")
        if reverse_gap_rows:
            df_rev_gaps = pd.DataFrame(reverse_gap_rows)
            df_rev_gaps.drop_duplicates(subset=["Reference_ID_Anchor", "Corporate_Audit_File", "Control_Description"], inplace=True)
            df_rev_gaps.sort_values(by=["Corporate_Audit_File", "Reference_ID_Anchor"], inplace=True)
        else:
            df_rev_gaps = pd.DataFrame(columns=[
                "Reference_ID_Anchor", "Raw_Reference_String", "Corporate_Audit_File", 
                "Control_Description", "Item_Type", "PowerShell_Args"
            ])
            
        df_rev_gaps.to_excel(writer, sheet_name="Comprehensive_Reference_Maps", index=False)
        writer.sheets["Comprehensive_Reference_Maps"].sheet_properties.tabColor = "D35400"  # Vibrant Orange Tab
        autofit_excel_columns(writer, "Comprehensive_Reference_Maps")

        # 6. Generate the Executive Dashboard Summary Tab
        print("5. Formatting dashboard overview metrics panel...")
        df_dash = pd.DataFrame(dashboard_summary)
        df_dash.to_excel(writer, sheet_name="Executive_Dashboard", index=False)
        writer.sheets["Executive_Dashboard"].sheet_properties.tabColor = "2980B9"
        autofit_excel_columns(writer, "Executive_Dashboard")

        # 7. Generate NEW Flattened Framework Control Dashboard (Matches Target Format)
        print("6. Building Flattened Framework Control Dashboard...")

        # Combine anchors
        potential_series = pd.concat(all_compiled_potential_anchors, ignore_index=True) if all_compiled_potential_anchors else pd.Series(dtype=str)
        active_series = pd.concat(all_compiled_active_anchors, ignore_index=True) if all_compiled_active_anchors else pd.Series(dtype=str)

        # Count occurrences
        potential_counts = potential_series.value_counts().to_dict()
        active_counts = active_series.value_counts().to_dict()

        # NIST Family Names
        NIST_FAMILY_NAMES = {
            "AC": "Access Control",
            "AT": "Awareness and Training",
            "AU": "Audit and Accountability",
            "CA": "Assessment, Authorization, and Monitoring",
            "CM": "Configuration Management",
            "CP": "Contingency Planning",
            "IA": "Identification and Authentication",
            "IR": "Incident Response",
            "MA": "Maintenance",
            "MP": "Media Protection",
            "PE": "Physical and Environmental Protection",
            "PL": "Planning",
            "PM": "Program Management",
            "PS": "Personnel Security",
            "PT": "PII Processing and Transparency",
            "RA": "Risk Assessment",
            "SA": "System and Services Acquisition",
            "SC": "System and Communications Protection",
            "SI": "System and Information Integrity",
            "SR": "Supply Chain Risk Management"
        }

        df_fw = df_frameworks.copy()
        # ✅ ADD SCORING + STATUS
        df_fw["Potential"] = df_fw["Join_Anchor"].map(lambda x: potential_counts.get(x, 0))
        df_fw["Actual"] = df_fw["Join_Anchor"].map(lambda x: active_counts.get(x, 0))
        df_fw["Gap"] = df_fw["Potential"] - df_fw["Actual"]

        df_fw["Compliance %"] = df_fw.apply(
            lambda r: (r["Actual"] / r["Potential"]) if r["Potential"] > 0 else 1,
            axis=1
        )

        def classify_gap(row):
            if row["Potential"] == 0:
                return "N/A"
            ratio = row["Actual"] / row["Potential"]
            if ratio >= 0.95:
                return "Compliant"
            elif ratio >= 0.6:
                return "Partial"
            else:
                return "High Gap"

        df_fw["Status"] = df_fw.apply(classify_gap, axis=1)

        # Detect columns dynamically
        name_col = next((c for c in df_fw.columns if "NAME" in c.upper() or "TITLE" in c.upper()), None)
        desc_col = next((c for c in df_fw.columns if "TEXT" in c.upper() or "DESC" in c.upper()), None)

        records = []

        # ✅ Build flattened rows
        for _, row in df_fw.iterrows():
            anchor = row["Join_Anchor"]

            if not anchor or str(anchor).strip() == "":
                continue

            control_id = str(anchor)
            family_code = control_id.split("-")[0]
            family_name = NIST_FAMILY_NAMES.get(family_code, "Other")

            title = str(row[name_col]) if name_col and name_col in row else ""
            description = str(row[desc_col]) if desc_col and desc_col in row else ""

            potential = potential_counts.get(control_id, 0)
            actual = active_counts.get(control_id, 0)
            gap = potential - actual

            # ✅ CALCULATE METRICS HERE (NOT EARLIER!)
            compliance = (actual / potential) if potential > 0 else 1

            if potential == 0:
                status = "N/A"
            elif compliance >= 0.95:
                status = "Compliant"
            elif compliance >= 0.6:
                status = "Partial"
            else:
                status = "High Gap"

            # ✅ RISK SEVERITY CLASSIFICATION
            if potential == 0:
                risk = "None"
            elif compliance >= 0.95:
                risk = "Low"
            elif compliance >= 0.6:
                risk = "Medium"
            else:
                risk = "High"


        records.append({
            "Control Family": family_name,
            "Control ID": control_id,
            "Control Title": title,
            "Description": description,
            "Potential": potential,
            "Actual": actual,
            "Gap": gap,
            "Compliance %": compliance,
            "Status": status,
            "Risk Level": risk   # ✅ NEW
        })


        df_dashboard = pd.DataFrame(records)

        # ✅ Build FAMILY ROLLUPS (AC, AT, etc.)
        family_rollups = (
            df_dashboard.groupby("Control Family")[["Potential", "Actual", "Gap"]]
            .sum()
            .reset_index()
        )

        family_rollups["Control ID"] = family_rollups["Control Family"].apply(lambda x: x.split()[0] if " " in x else x)
        family_rollups["Control Title"] = family_rollups["Control Family"]
        family_rollups["Description"] = ""

        family_rollups["Compliance %"] = family_rollups.apply(
            lambda r: (r["Actual"] / r["Potential"]) if r["Potential"] > 0 else 1,
            axis=1
        )

        family_rollups["Status"] = family_rollups.apply(
            lambda r: "N/A" if r["Potential"] == 0
            else "Compliant" if (r["Actual"] / r["Potential"]) >= 0.95
            else "Partial" if (r["Actual"] / r["Potential"]) >= 0.6
            else "High Gap",
            axis=1
        )

        family_rollups["Risk Level"] = family_rollups.apply(
            lambda r: "None" if r["Potential"] == 0
            else "Low" if (r["Actual"] / r["Potential"]) >= 0.95
            else "Medium" if (r["Actual"] / r["Potential"]) >= 0.6
            else "High",
            axis=1
        )

        # ✅ Merge detail + rollups with spacing
        final_rows = []
        for family in df_dashboard["Control Family"].unique():
            fam_df = df_dashboard[df_dashboard["Control Family"] == family]
            final_rows.append(fam_df)

            # Add rollup row
            roll = family_rollups[family_rollups["Control Family"] == family]
            final_rows.append(roll)

            # Spacer row
            spacer = pd.DataFrame([{
                "Control Family": "",
                "Control ID": "",
                "Control Title": "",
                "Description": "",
                "Potential": "",
                "Actual": "",
                "Gap": "",
                "Compliance %": "",
                "Status": "",
                "Risk Level": ""
            }])
            final_rows.append(spacer)

        df_final_dashboard = pd.concat(final_rows, ignore_index=True)
        # =========================
        # EXECUTIVE SCORECARD DATA
        # =========================

        # Remove blank spacer rows
        df_clean = df_final_dashboard[df_final_dashboard["Control ID"] != ""].copy()

        # Keep only real controls (exclude family rollups)
        df_controls = df_clean[df_clean["Control ID"].str.contains("-")]

        # Aggregate by family
        df_family_summary = (
            df_controls.groupby("Control Family")[["Potential", "Actual"]]
            .sum()
            .reset_index()
        )

        # =========================
        # HEATMAP DATA BUILD
        # =========================

        df_heatmap = df_family_summary.copy()

        # Convert to percentage scale (0–100)
        # ✅ REBUILD MISSING COLUMNS BEFORE USING THEM
        df_heatmap["Gap"] = df_heatmap["Potential"] - df_heatmap["Actual"]

        df_heatmap["Compliance %"] = df_heatmap.apply(
            lambda r: (r["Actual"] / r["Potential"]) * 100 if r["Potential"] > 0 else 100,
            axis=1
        )


        df_heatmap.sort_values(by="Compliance %", inplace=True)

        df_family_summary["Gap"] = df_family_summary["Potential"] - df_family_summary["Actual"]

        df_family_summary["Compliance %"] = df_family_summary.apply(
            lambda r: (r["Actual"] / r["Potential"]) if r["Potential"] > 0 else 1,
            axis=1
        )

        # Sort worst → best
        df_family_summary.sort_values(by="Compliance %", inplace=True)

        # Top 5 risk families
        top_risk_families = df_family_summary.head(5)

        # Overall score
        total_potential = df_controls["Potential"].sum()
        total_actual = df_controls["Actual"].sum()

        overall_compliance = (total_actual / total_potential) if total_potential > 0 else 1


        df_final_dashboard = df_final_dashboard[
            [
                "Control Family",
                "Control ID",
                "Control Title",
                "Description",
                "Potential",
                "Actual",
                "Gap",
                "Compliance %",
                "Status",
                "Risk Level"   # ✅ NEW
            ]
        ]

        # ✅ Sort (optional: preserves grouping better without strict sort)
        # df_final_dashboard.sort_values(by=["Control Family", "Control ID"], inplace=True)

        # ✅ Write to Excel
        sheet_name = "Framework_Control_Dashboard"

        df_final_dashboard.to_excel(writer, sheet_name=sheet_name, index=False)

        writer.sheets[sheet_name].sheet_properties.tabColor = "E67E22"

        autofit_excel_columns(writer, sheet_name)
        format_dashboard_sheet(writer, sheet_name)
        # =========================
        # EXECUTIVE SCORECARD SHEET
        # =========================

        scorecard_sheet = "Executive_Scorecard"

        # KPI SUMMARY
        df_kpi = pd.DataFrame([
            {"Metric": "Total Controls Evaluated", "Value": len(df_controls)},
            {"Metric": "Total Potential Checks", "Value": total_potential},
            {"Metric": "Total Passed Checks", "Value": total_actual},
            {"Metric": "Overall Compliance %", "Value": overall_compliance}
        ])

        df_kpi.to_excel(writer, sheet_name=scorecard_sheet, startrow=0, index=False)

        # Top Risk Families
        top_risk_families.to_excel(writer, sheet_name=scorecard_sheet, startrow=7, index=False)
        from openpyxl.chart import BarChart, Reference, PieChart

    ws_score = writer.sheets[scorecard_sheet]

    # BAR CHART – compliance by family
    bar = BarChart()
    bar.title = "Top Risk Control Families"

    data = Reference(ws_score, min_col=5, min_row=8, max_row=8 + len(top_risk_families))
    cats = Reference(ws_score, min_col=1, min_row=9, max_row=8 + len(top_risk_families))

    bar.add_data(data, titles_from_data=True)
    bar.set_categories(cats)

    ws_score.add_chart(bar, "G2")

    # PIE CHART – overall compliance
    ws_score["E2"] = "Passed"
    ws_score["E3"] = "Failed"
    ws_score["F2"] = total_actual
    ws_score["F3"] = total_potential - total_actual

    pie = PieChart()
    pie.title = "Overall Compliance"

    data = Reference(ws_score, min_col=6, min_row=2, max_row=3)
    labels = Reference(ws_score, min_col=5, min_row=2, max_row=3)

    pie.add_data(data)
    pie.set_categories(labels)

    ws_score.add_chart(pie, "G18")

    format_scorecard_sheet(writer, scorecard_sheet)
    autofit_excel_columns(writer, scorecard_sheet)
    # =========================
    # HEATMAP SHEET
    # =========================

    heatmap_sheet = "Control_Heatmap"

    df_heatmap.to_excel(writer, sheet_name=heatmap_sheet, index=False)
    format_heatmap_sheet(writer, heatmap_sheet)
    autofit_excel_columns(writer, heatmap_sheet)

    print("\n=======================================================")
    print(f" PIPELINE SUCCESS: Ultimate Reference Mapping Matrix Built!")
    print(f" Deliverable Path Location: {FINAL_OUTPUT_PATH}")
    print("=======================================================\n")


if __name__ == "__main__":
    build_unified_compliance_matrix()
