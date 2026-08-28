#!/usr/bin/env python3
"""Compare_Audits.py

Finds duplicate checks between an OG (reference) audit file and a New audit file.
Matches are identified by fingerprinting the powershell_args content of each
active <custom_item> block.  For items without powershell_args (native format),
the check-specific fields are fingerprinted instead.

Commented blocks (lines starting with #) are skipped.
Duplicates are listed in the order they appear in the New file.

Usage:
    python Compare_Audits.py     <- prompts for OG and New file paths
"""

import os
import re
from datetime import datetime

OUTPUT_DIR = r"C:\PySC"

# =============================================================================
# SECEDIT MAPPINGS (for native-format items)
# =============================================================================

LOCKOUT_SEQ = {
    "LOCKOUT_DURATION":  "lockoutduration",
    "LOCKOUT_THRESHOLD": "lockoutbadcount",
    "LOCKOUT_RESET":     "resetlockoutcount",
}

PASSWORD_SEQ = {
    "ENFORCE_PASSWORD_HISTORY": "passwordhistorysize",
    "MAXIMUM_PASSWORD_AGE":     "maximumpasswordage",
    "MINIMUM_PASSWORD_AGE":     "minimumpasswordage",
    "MINIMUM_PASSWORD_LENGTH":  "minimumpasswordlength",
    "COMPLEXITY_REQUIREMENTS":  "passwordcomplexity",
    "REVERSIBLE_ENCRYPTION":    "cleartextpassword",
    "FORCE_LOGOFF":             "forcelogoffwhenhourexpire",
    "LOCKOUT_ADMINS":           "allowadministratorlockout",
}

# Map 'net accounts | Select-string' keywords to canonical secedit key names
NET_ACCOUNTS_MAP = {
    "password history":   "passwordhistorysize",
    "maximum password":   "maximumpasswordage",
    "minimum password age": "minimumpasswordage",
    "password length":    "minimumpasswordlength",
    "lockout observation": "resetlockoutcount",
    "threshold":          "lockoutbadcount",
    "lockout duration":   "lockoutduration",
}

REG_ABBREV = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU":  "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}

# =============================================================================
# PATH NORMALIZER
# =============================================================================

def normalize_reg_path(raw):
    """Normalise a registry path to lowercase HKEY_* form with no prefix/colon."""
    s = raw.strip().strip('"').strip("'")
    s = re.sub(r'^Registry::', '', s, flags=re.IGNORECASE)
    for short, full in REG_ABBREV.items():
        # PowerShell drive form:  HKLM:\path
        if s.upper().startswith(short + ":\\"):
            s = full + "\\" + s[len(short) + 2:]
            break
        # Plain abbreviation:     HKLM\path
        if s.upper().startswith(short + "\\"):
            s = full + s[len(short):]
            break
    return s.lower()

# =============================================================================
# FINGERPRINT EXTRACTORS
# =============================================================================

def _extract_net_accounts_key(s):
    s_lower = s.lower()
    for keyword, canonical in NET_ACCOUNTS_MAP.items():
        if keyword in s_lower: # Catch any net accounts command mentioning 'password history'
            return f"secedit:{canonical}"
    return None


def extract_fingerprint_from_ps(ps_args):
    """
    Return a normalised fingerprint string for the given powershell_args value,
    or None if no recognisable pattern is found.
    """
    s = ps_args.strip().strip('"').strip("'")
    s_lower = s.lower()

    # 1. System Info / Computer Info (Item #1)
    if "get-computerinfo" in s_lower or "csdomain" in s_lower:
        return "info:system_identification"

    # 2. Network Info / TLS Server check (Item #2)
    if "get-netipconfiguration" in s_lower or "schannel\\protocols\\tls" in s_lower:
        return "info:network_tls_info"

    # 3. Screensaver checks (Items #8, #9, #10, #23)
    if "screensaveactive" in s_lower:
        return "registry:hkey_users|screensaveactive"
    if "screensaverissecure" in s_lower:
        return "registry:hkey_users|screensaverissecure"
    if "screensavergraceperiod" in s_lower:
        return "registry:hkey_local_machine\\software\\microsoft\\windows nt\\currentversion\\winlogon|screensavergraceperiod"

    # 4. net accounts (Broad check for both old and new styles)
    if "net accounts" in s_lower:
        result = _extract_net_accounts_key(s)
        if result:
            return result

    # 5. User rights (secedit /areas USER_RIGHTS)
    if "/areas user_rights" in s_lower:
        m = re.search(r'\^([A-Za-z][A-Za-z0-9]+)\\s\*=', s, re.IGNORECASE)
        if m:
            return f"userrights:{m.group(1).lower()}"

    # 6. Secedit password / lockout (no USER_RIGHTS)
    if "secedit" in s_lower:
        m = re.search(r'\^([A-Za-z][A-Za-z0-9]+)\\s\*=', s, re.IGNORECASE)
        if m:
            return f"secedit:{m.group(1).lower()}"

    # 7. Auditpol subcategory
    if "auditpol" in s_lower:
        m = re.search(r"auditpol\s+/get\s+/[Ss]ubcategory:'([^']+)'", s)
        if m:
            return f"auditpol:{m.group(1).lower()}"

    # 8. Registry: Legacy "Value Not Found" wrapper scripts
    legacy_wrap_m = re.search(r"Get-ItemProperty\s+-Path\s+'([^']+)'\)\.([A-Za-z0-9_]+)", s, re.IGNORECASE)
    if legacy_wrap_m:
        path = normalize_reg_path(legacy_wrap_m.group(1))
        prop = legacy_wrap_m.group(2).lower()
        return f"registry:{path}|{prop}"

    # 9. Registry: Standard Get-ItemProperty (both styles)
    path_m = re.search(r"Get-ItemProperty\s+-Path\s+'([^']+)'", s, re.IGNORECASE)
    if path_m:
        path = normalize_reg_path(path_m.group(1))
        dot_m = re.search(r"\)\s*\.\s*([A-Za-z0-9_]+)", s)
        bracket_m = re.search(r"\$p\.'([^']+)'", s)
        psobj_m = re.search(r"PSObject\.Properties\['([^']+)'\]", s)
        prop_match = bracket_m or psobj_m or dot_m
        if prop_match:
            prop = prop_match.group(1).lower()
            return f"registry:{path}|{prop}"
        return f"registry:{path}"

    # 10. Services
    service_m = re.search(r"Get-Service\s+(?:-Name\s+)?'([^']+)'", s, re.IGNORECASE)
    if service_m:
        return f"service:{service_m.group(1).lower()}"

    # 11. Test-Path (REG_CHECK style)
    m = re.search(r"Test-Path\s+(?:-Path\s+)?'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"regcheck:{normalize_reg_path(m.group(1))}"

    # 12. Accounts
    if "s-1-5-*-500" in s_lower or "s-1-5-21.*-500" in s_lower:
        return "account:builtin_administrator"
    if "s-1-5-*-501" in s_lower or "s-1-5-21.*-501" in s_lower:
        return "account:guest"
    if "anonymousnamelookup" in s_lower:
        return "lsa:anonymousnamelookup"
    m = re.search(r"Get-LocalUser\s+-Name\s+'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"account:{m.group(1).lower()}"

    # 13. WMI
    m = re.search(r"Get-WmiObject\s+-Namespace\s+'([^']+)'\s+-Query\s+'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"wmi:{m.group(1).lower()}|{m.group(2).lower()}"
    
    #14 Specific Disabled and Enabled Components
    if "disabledcomponents" in s_lower and "tcpip6" in s_lower:
        return "registry:hkey_local_machine\\system\\currentcontrolset\\services\\tcpip6\\parameters|disabledcomponents"
        
    if "enablesmb1protocol" in s_lower or "smb1_server" in s_lower:
        return "runtime:smb1_server"
    return None


def extract_fingerprint_from_fields(fields):
    """
    Fallback fingerprint extraction for native-format items
    (PASSWORD_POLICY, LOCKOUT_POLICY, REGISTRY_SETTING, etc.).
    """
    item_type = fields.get("type", "").strip()

    if item_type == "REGISTRY_SETTING":
        path = normalize_reg_path(fields.get("reg_key", ""))
        prop = fields.get("reg_item", "").strip().strip('"').lower()
        return f"registry:{path}|{prop}"

    if item_type == "REG_CHECK":
        path = normalize_reg_path(fields.get("value_data", ""))
        ki   = fields.get("key_item", "").strip().strip('"').lower()
        return f"regcheck:{path}" + (f"|{ki}" if ki else "")

    if item_type == "PASSWORD_POLICY":
        key = PASSWORD_SEQ.get(
            fields.get("password_policy", "").strip(),
            fields.get("password_policy", "").strip().lower()
        )
        return f"secedit:{key}"

    if item_type == "LOCKOUT_POLICY":
        key = LOCKOUT_SEQ.get(
            fields.get("lockout_policy", "").strip(),
            fields.get("lockout_policy", "").strip().lower()
        )
        return f"secedit:{key}"

    if item_type == "AUDIT_POLICY_SUBCATEGORY":
        sub = fields.get("audit_policy_subcategory", "").strip().strip('"').lower()
        return f"auditpol:{sub}"

    if item_type == "USER_RIGHTS_POLICY":
        right = fields.get("right_type", "").strip().lower()
        return f"userrights:{right}"

    if item_type == "CHECK_ACCOUNT":
        acct = fields.get("account_type", "").strip().upper()
        if "GUEST" in acct:
            return "account:guest"
        return "account:builtin_administrator"

    if item_type == "ANONYMOUS_SID_SETTING":
        return "lsa:anonymousnamelookup"

    if item_type in ("BANNER_CHECK",):
        path = normalize_reg_path(fields.get("reg_key", ""))
        prop = fields.get("reg_item", "").strip().strip('"').lower()
        return f"registry:{path}|{prop}"

    if item_type == "WMI_POLICY":
        ns = fields.get("wmi_namespace", "").strip().strip('"').lower()
        q  = fields.get("wmi_request",   "").strip().strip('"').lower()
        return f"wmi:{ns}|{q}"

    return None


def get_fingerprint(fields):
    """Return the best available fingerprint for a parsed item dict."""
    ps = fields.get("powershell_args", "")
    if ps:
        fp = extract_fingerprint_from_ps(ps)
        if fp:
            return fp
    return extract_fingerprint_from_fields(fields)

# =============================================================================
# PARSER
# =============================================================================

def parse_custom_items(filepath):
    """
    Parse all *active* <custom_item> blocks from an audit file.
    A block is active when its opening <custom_item> tag line is not commented
    (does not start with # after stripping whitespace).
    Within an active block, lines starting with # are skipped (commented fields).
    Returns a list of dicts: {field_name: value, ..., '_raw_lines': [str, ...]}
    '_raw_lines' holds every line of the block (including the open/close tags and
    any commented lines within the block) for verbatim re-insertion.
    """
    items = []

    with open(filepath, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    in_item      = False
    fields       = {}
    current_key  = None
    current_buf  = []
    raw_lines    = []

    for raw_line in lines:
        line     = raw_line.rstrip()
        stripped = line.lstrip()

        # ---- outside a block -----------------------------------------------
        if not in_item:
            # Ignore full-line comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if re.match(r"\s*<custom_item>", line):
                in_item     = True
                fields      = {}
                current_key = None
                current_buf = []
                raw_lines   = [line]
            continue

        # ---- inside a block -----------------------------------------------
        # Collect every raw line (commented or not) for verbatim re-insertion
        raw_lines.append(line)

        # Close tag
        if re.match(r"\s*</custom_item>", line):
            if current_key:
                fields[current_key] = "\n".join(current_buf).strip()
            # Validate: must have a type field that isn't empty
            if fields.get("type", "").strip():
                fields["_raw_lines"] = list(raw_lines)
                items.append(dict(fields))
            in_item      = False
            fields       = {}
            current_key  = None
            current_buf  = []
            raw_lines    = []
            continue

        # Skip commented-out lines within a block (for field parsing only)
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Parse key : value
        m = re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*)", line)
        if m:
            if current_key:
                fields[current_key] = "\n".join(current_buf).strip()
            current_key = m.group(1)
            current_buf = [m.group(2)]
            
            # --- ADD THIS LOGIC HERE ---
            # Capture the original description to ensure replacement works later
            if current_key == "description":
                # Store the exact text inside the quotes as seen in the file
                fields["_original_description_from_file"] = m.group(2).strip().strip('"')
            # ---------------------------
    return items

# =============================================================================
# MAIN
# =============================================================================

def main():
    og_path  = input("Enter OG (reference) file path : ").strip().strip('"').strip("'")
    new_path = input("Enter New file path            : ").strip().strip('"').strip("'")

    for label, path in [("OG", og_path), ("New", new_path)]:
        if not os.path.isfile(path):
            print(f"ERROR: {label} file not found: {path}")
            return

    print(f"\nParsing OG file  : {og_path}")
    og_items = parse_custom_items(og_path)
    print(f"  {len(og_items)} active items found")

    print(f"Parsing New file : {new_path}")
    new_items = parse_custom_items(new_path)
    print(f"  {len(new_items)} active items found")

    # ------------------------------------------------------------------
    # Build fingerprint → item(s) map for OG file
    # ------------------------------------------------------------------
    og_fp_map   = {}   # fingerprint -> list of OG item dicts
    og_no_fp    = []   # OG items that could not be fingerprinted
    for item in og_items:
        fp = get_fingerprint(item)
        if fp:
            og_fp_map.setdefault(fp, []).append(item)
        else:
            og_no_fp.append(item)

    print(f"  {len(og_fp_map)} unique OG fingerprints  "
          f"({len(og_no_fp)} OG item(s) could not be fingerprinted)")

    # ------------------------------------------------------------------
    # 1. Find New items whose fingerprint matches an OG item (duplicates)
    # ------------------------------------------------------------------
    duplicates = []
    new_no_fp = 0
    seen_fps = set()        
    matched_og_fps = set()        

    for new_item in new_items:
        fp = get_fingerprint(new_item)
        if not fp:
            new_no_fp += 1
            continue
        if fp in og_fp_map:
            matched_og_fps.add(fp)
            new_desc = new_item.get("description", "").strip().strip('"')
            for og_item in og_fp_map[fp]:
                og_desc = og_item.get("description", "").strip().strip('"')
                pair_key = (fp, og_desc, new_desc)
                if pair_key not in seen_fps:
                    seen_fps.add(pair_key)
                    duplicates.append({"fp": fp, "og_desc": og_desc, "new_desc": new_desc})

    print(f"\n  Duplicate checks found : {len(duplicates)}")

    # ------------------------------------------------------------------
    # 2. Identify orphaned OG items
    # ------------------------------------------------------------------
    orphaned = []
    for item in og_items:
        fp = get_fingerprint(item)
        if not fp or fp not in matched_og_fps:
            orphaned.append(item)

    print(f"  Orphaned OG items      : {len(orphaned)}")

    # ------------------------------------------------------------------
    # 3. Detect Similar Items (Add - Client / - Service)
    # ------------------------------------------------------------------
    similar_log = []
    prop_map = {}

    for item in new_items + orphaned:
        fp = get_fingerprint(item)
        if fp and fp.startswith("registry:"):
            parts = fp.split('|')
            if len(parts) == 2:
                path_val, prop_val = parts[0], parts[1]
                prop_map.setdefault(prop_val, []).append((item, path_val))

    for prop, entries in prop_map.items():
        if len(entries) > 1:
            for item, path in entries:
                label = path.split('\\')[-1].capitalize()
                old_desc = item.get("description", "").strip().strip('"')
                
                if label not in old_desc:
                    labeled_desc = f"{old_desc} - {label}"
                    item["description"] = f'"{labeled_desc}"'
                    
                    if "_raw_lines" in item:
                        new_raw = []
                        for line in item["_raw_lines"]:
                            if re.search(r'^\s*description\s*:', line):
                                m = re.match(r'^(\s*description\s*:\s*)', line)
                                prefix = m.group(1) if m else "  description : "
                                new_raw.append(f'{prefix}"{labeled_desc}"')
                            else:
                                new_raw.append(line)
                        item["_raw_lines"] = new_raw
                    similar_log.append(f"    {old_desc} -> Added ({label})")
            similar_log.append("")

    # ------------------------------------------------------------------
    # 4. Write comparison report
    # ------------------------------------------------------------------
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    new_base = os.path.splitext(os.path.basename(new_path))[0]
    og_base  = os.path.splitext(os.path.basename(og_path))[0]
    outfile  = os.path.join(OUTPUT_DIR, f"{new_base}-vs-{og_base}-duplicates.txt")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 79

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(f"{sep}\nAUDIT FILE COMPARISON REPORT\nGenerated : {ts}\n{sep}\n\n")
        
        f.write(f"SIMILAR ITEMS RELABELLED\n{sep}\n")
        if not similar_log: f.write("None.\n")
        else:
            for s in similar_log: f.write(f"{s}\n")

        f.write(f"\nDUPLICATE CHECKS FOUND ({len(duplicates)})\n{sep}\n")
        for i, d in enumerate(duplicates, 1):
            f.write(f"{i:>4}. OG : \"{d['og_desc']}\"\n      New: \"{d['new_desc']}\"\n      Key: {d['fp']}\n\n")

        f.write(f"\nORPHANED OG ITEMS\nTotal : {len(orphaned)}\n{sep}\n")
        for i, item in enumerate(orphaned, 1):
            d = item.get('description','').strip().strip('"')
            f.write(f"{i:>4}. \"{d}\"\n      Key: {get_fingerprint(item)}\n\n")

    print(f"\nReport written to: {outfile}")

    # ------------------------------------------------------------------
    # 5. Build _Integrated.audit
    # ------------------------------------------------------------------
    if not orphaned:
        print("\nNo orphaned items — _Integrated file not needed.")
        return

    # Read the fresh New file into a string
    with open(new_path, encoding="utf-8", errors="replace") as f:
        new_content = f.read()

    # --- A. INJECT LABELS ---
    print("Applying labels...")
    audit_pattern = re.compile(r'^1\.\d{4}\s*-\s*MSWRK', re.IGNORECASE)

    # Track descriptions of non-OG items so we can identify them after
    # finalize_integrated_formatting() changes colon alignment.
    non_og_descs = set()

    for item in new_items:
        labeled_desc = item.get("description", "").strip().strip('"')
        original_desc = item.get("_original_description_from_file")

        # Apply label changes to new_content
        if original_desc and labeled_desc and original_desc != labeled_desc:
            new_content = new_content.replace(f'"{original_desc}"', f'"{labeled_desc}"')

        # Track blocks NOT in OG for the commented variant
        if audit_pattern.match(labeled_desc):
            fp = get_fingerprint(item)
            if not fp or fp not in og_fp_map:
                non_og_descs.add(labeled_desc)

    # --- B. PREPARE ORPHANED BLOCKS ---
    orphaned_blocks = ["\n".join(item["_raw_lines"]) for item in orphaned]
    blocks_text = "\n\n" + "\n\n".join(orphaned_blocks) + "\n"

    # --- C. INSERT ORPHANS BEFORE LAST </then> ---
    then_pattern = re.compile(r'[ \t]*</then>', re.IGNORECASE)
    matches = list(then_pattern.finditer(new_content))
    if matches:
        insert_pos = matches[-1].start()
        new_content = new_content[:insert_pos] + blocks_text + new_content[insert_pos:]
    else:
        print("\nERROR: Could not find </then> insertion point.")
        return

    # --- D. FINAL RENUMBERING & ALIGNMENT ---
    existing_nums = re.findall(r'"1\.([0-9]{4})\s*-\s*MSWRK', new_content)
    last_num = max(int(n) for n in existing_nums) if existing_nums else 0
    new_content, total_renumbered = finalize_integrated_formatting(new_content, start_after=last_num)

    # --- D2. BUILD non_og_blocks FROM FINALIZED CONTENT ---
    # Must happen AFTER finalize so colon-aligned text matches what's in the file.
    non_og_blocks = []
    _desc_re = re.compile(r'description\s*:\s*"([^"]+)"', re.IGNORECASE)
    _in_blk = False
    _blk_lines = []
    for _line in new_content.split('\n'):
        _s = _line.strip()
        if not _in_blk:
            if _s == '<custom_item>':
                _in_blk = True
                _blk_lines = [_line]
        else:
            _blk_lines.append(_line)
            if _s == '</custom_item>':
                _block_text = '\n'.join(_blk_lines)
                _dm = _desc_re.search(_block_text)
                if _dm and _dm.group(1).strip() in non_og_descs:
                    _commented = '\n'.join([f"# {l}" for l in _blk_lines])
                    non_og_blocks.append((_block_text, _commented))
                _in_blk = False
                _blk_lines = []

    # --- E. WRITE FILE 1: Full (all entries, no comments) ---
    integrated_path = os.path.join(OUTPUT_DIR, f"{new_base}_Integrated.audit")
    with open(integrated_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    validate_audit_output(integrated_path)

    # --- F. WRITE FILE 2: OG-only (non-OG items commented out) ---
    commented_content = new_content
    for search_block, commented_block in non_og_blocks:
        commented_content = commented_content.replace(search_block, commented_block)

    commented_path = os.path.join(OUTPUT_DIR, f"{new_base}_Integrated_OG-only.audit")
    with open(commented_path, "w", encoding="utf-8") as f:
        f.write(commented_content)
    validate_audit_output(commented_path)

    # --- FINAL SUMMARY ---
    print(f"\n{'=' * 60}")
    print(f"OUTPUT FILES")
    print(f"{'=' * 60}")
    print(f"  Report (.txt)      : {outfile}")
    print(f"  All entries        : {integrated_path}")
    print(f"  OG-only (commented): {commented_path}")
    print(f"{'=' * 60}")
    print(f"  {len(orphaned_blocks)} legacy OG blocks appended")
    print(f"  {total_renumbered} total items renumbered")
    print(f"  {len(non_og_blocks)} non-OG blocks commented out in OG-only file")
    print(f"{'=' * 60}\n")


def validate_audit_output(filepath):
    """Validate a finished .audit file and report any structural or field problems.
    Only examines uncommented <custom_item> blocks (lines starting with # are skipped).
    """
    import re as _re
    print(f"\n--- Validating output: {filepath} ---")
    with open(filepath, 'r', encoding='utf-8') as _f:
        _lines = _f.readlines()

    # Collect only active (uncommented) blocks by walking line-by-line
    _blocks = []
    _in_block = False
    _buf = []
    for _line in _lines:
        _s = _line.strip()
        if not _in_block:
            if _s == '<custom_item>':   # uncommented open tag only
                _in_block = True
                _buf = [_line]
        else:
            _buf.append(_line)
            if _s == '</custom_item>':
                _blocks.append(''.join(_buf))
                _in_block = False
                _buf = []

    _issues = []
    for _i, _body in enumerate(_blocks, 1):
        _dm = _re.search(r'description\s*:\s*"([^"]+)"', _body)
        _desc = _dm.group(1) if _dm else '(no description)'
        _missing = []
        if not _re.search(r'^\s*type\s*:', _body, _re.M):                       _missing.append('type')
        if not _re.search(r'^\s*description\s*:', _body, _re.M):                _missing.append('description')
        if not _re.search(r'^\s*(value_type|check_type)\s*:', _body, _re.M):   _missing.append('value_type')
        if not _re.search(r'^\s*value_data\s*:', _body, _re.M):                 _missing.append('value_data')
        if _re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', _body):              _missing.append('CONTROL_CHARS')
        if 'AUDIT_POWERSHELL' in _body and not _re.search(r'powershell_args\s*:', _body):
            _missing.append('missing_powershell_args')
        if _missing:
            _issues.append((_i, _desc[:70], _missing))

    # Only check powershell_args on non-comment lines
    _ps_lines = [(i + 1, _lines[i].strip()) for i in range(len(_lines))
                 if not _lines[i].strip().startswith('#')
                 and _re.match(r'\s*powershell_args\s*:', _lines[i])]
    _quote_issues = [(ln, l[:100]) for ln, l in _ps_lines
                     if not _re.match(r'\s*powershell_args\s*:\s*".*"', l)]

    _total = len(_blocks)
    if _issues:
        print(f"  FIELD ERRORS ({len(_issues)} block(s)):")
        for _item in _issues:
            print(f"    block {_item[0]}: {_item[1]}")
            print(f"      problems: {_item[2]}")
    else:
        print(f"  All {_total} active custom_item blocks: OK")

    if _quote_issues:
        print(f"  POWERSHELL_ARGS QUOTE ERRORS ({len(_quote_issues)}):")
        for _q in _quote_issues:
            print(f"    line {_q[0]}: {_q[1]}")
    else:
        print(f"  All {len(_ps_lines)} powershell_args outer quotes: OK")

    _ok = not _issues and not _quote_issues
    print(f"  Result: {'PASS' if _ok else 'FAIL — see errors above'}")
    return _ok


def finalize_integrated_formatting(content, start_after=0):
    """Renumber descriptions and align colons for the final merged file.

    Existing numbered items (1.XXXX - MSWRK) keep their original numbers.
    Un-numbered items (orphans appended from OG) are assigned sequential numbers
    starting from start_after+1.
    """

    # 1. Renumbering
    desc_field_re = re.compile(r'(^[ \t]*description\s*:\s*")([^"]+)(")', re.MULTILINE)
    next_new = start_after + 1
    numbered_re = re.compile(r'^1\.([0-9]{4})\s*-\s*MSWRK\s*-\s*')

    def replacer(m):
        nonlocal next_new
        prefix_indent = m.group(1)
        old_text = m.group(2)

        nm = numbered_re.match(old_text)
        if nm:
            # Already has a 1.XXXX number — preserve it exactly
            return m.group(0)

        # Orphan: strip any old prefix and assign the next sequential number
        parts = old_text.split(" - ")
        if "MSWRK" in old_text and len(parts) >= 3:
            clean_text = " - ".join(parts[2:])
        else:
            clean_text = parts[-1]

        num = next_new
        next_new += 1
        return f'{prefix_indent}1.{num:04d} - MSWRK - {clean_text.strip()}"'

    # Only renumber within the first <then> ... last </then> block
    then_open_m = re.search(r'<then>', content, re.IGNORECASE)
    then_close_m = None
    for _m in re.finditer(r'</then>', content, re.IGNORECASE):
        then_close_m = _m

    if then_open_m and then_close_m and then_open_m.end() < then_close_m.start():
        before = content[:then_open_m.end()]
        middle = content[then_open_m.end():then_close_m.start()]
        after  = content[then_close_m.start():]
        middle = desc_field_re.sub(replacer, middle)
        content = before + middle + after
    else:
        content = desc_field_re.sub(replacer, content)
    total_renumbered = next_new - start_after - 1

    # 2. Re-align colons
    lines = content.splitlines()
    kv_re = re.compile(r'^(\s*)([A-Za-z0-9_]+)(\s+): ')
    max_col = 0
    for line in lines:
        m = kv_re.match(line)
        if m:
            col = len(m.group(1)) + len(m.group(2)) + len(m.group(3))
            if col > max_col: max_col = col
    
    aligned = []
    for line in lines:
        m = kv_re.match(line)
        if m:
            indent, key = m.group(1), m.group(2)
            rest = line[len(indent) + len(key) + len(m.group(3)):]
            aligned.append(f"{indent}{key}{' ' * (max_col - len(indent) - len(key))}{rest}")
        else:
            aligned.append(line)
    
    result = "\n".join(aligned)
    
    # 3. Double spacing cleanup
    result = re.sub(r'</custom_item>\s*\n(\s*<custom_item>)', r'</custom_item>\n\n\1', result)
    
    return result, total_renumbered


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
