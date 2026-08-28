#!/usr/bin/env python3
"""Compare_MSServer_Audits.py

Finds duplicate checks between an OG (reference) Windows Server audit file and
one or more New audit files.
Matches are identified by fingerprinting the powershell_args content of each
active <custom_item> block.  For items without powershell_args (native format),
the check-specific fields are fingerprinted instead.

Commented blocks (lines starting with #) are skipped.
Duplicates are listed in the order they appear in each New file.

Usage:
    python Compare_MSServer_Audits.py     <- prompts for OG path then New file paths
                                             (enter a blank line to finish adding files)
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
    """'net accounts | Select-string ...' → secedit:CANONICAL_KEY or None."""
    m = re.search(r"Select-[Ss]tring\s+'([^']+)'", s)
    keyword = m.group(1).lower() if m else None
    if keyword is None:
        # Unquoted form: Select-string threshold
        m2 = re.search(r"Select-[Ss]tring\s+([A-Za-z][A-Za-z0-9]+)", s, re.IGNORECASE)
        keyword = m2.group(1).lower() if m2 else None
    if keyword:
        for k, v in NET_ACCOUNTS_MAP.items():
            if k in keyword:
                return f"secedit:{v}"
    return None


def extract_fingerprint_from_ps(ps_args):
    """
    Return a normalised fingerprint string for the given powershell_args value,
    or None if no recognisable pattern is found.

    Handles both OG-style (net accounts / HKLM drive / (Get-ItemProperty).Prop)
    and converted-style (secedit ^Key match / Registry:: / $p.'Prop').
    """
    s = ps_args.strip().strip('"').strip("'")

    # ------------------------------------------------------------------ #
    # 1. net accounts | Select-string  (OG password/lockout style)
    # ------------------------------------------------------------------ #
    if "net accounts" in s.lower():
        result = _extract_net_accounts_key(s)
        if result:
            return result

    # ------------------------------------------------------------------ #
    # 2. User rights  (secedit /areas USER_RIGHTS)
    # ------------------------------------------------------------------ #
    if "/areas USER_RIGHTS" in s:
        m = re.search(r'\^([A-Za-z][A-Za-z0-9]+)\\s\*=', s)
        if m:
            return f"userrights:{m.group(1).lower()}"

    # ------------------------------------------------------------------ #
    # 3. Secedit password / lockout  (^KeyName\s*= pattern, no USER_RIGHTS)
    # ------------------------------------------------------------------ #
    m = re.search(r'\^([A-Za-z][A-Za-z0-9]+)\\s\*=', s)
    if m and "secedit" in s.lower():
        return f"secedit:{m.group(1).lower()}"

    # ------------------------------------------------------------------ #
    # 4. Auditpol subcategory  (both OG and converted styles)
    # ------------------------------------------------------------------ #
    m = re.search(r"auditpol\s+/get\s+/[Ss]ubcategory:'([^']+)'", s)
    if m:
        return f"auditpol:{m.group(1).lower()}"

    # ------------------------------------------------------------------ #
    # 5. Registry: Get-ItemProperty path + property name
    #    OG style:        (Get-ItemProperty -Path 'HKLM:\...').PropName
    #    Converted style: $p = Get-ItemProperty -Path 'Registry::...'
    #                     ... $p.'PropName'  or  PSObject.Properties['PropName']
    # ------------------------------------------------------------------ #
    path_m = re.search(r"Get-ItemProperty\s+-Path\s+'([^']+)'", s, re.IGNORECASE)

    if path_m:
        path = normalize_reg_path(path_m.group(1))

        # OG dot-access style: ).PropName  (at end or before semicolon)
        dot_m = re.search(r"\)\s*\.\s*([A-Za-z0-9_]+)", s)
        # Converted $p.'PropName' style
        bracket_m = re.search(r"\$p\.'([^']+)'", s)
        # PSObject.Properties['PropName'] style
        psobj_m = re.search(r"PSObject\.Properties\['([^']+)'\]", s)

        prop_match = bracket_m or psobj_m or dot_m
        if prop_match:
            prop = prop_match.group(1).lower()
            return f"registry:{path}|{prop}"
        return f"registry:{path}"

    # ------------------------------------------------------------------ #
    # 6. Test-Path (REG_CHECK style)
    # ------------------------------------------------------------------ #
    m = re.search(r"Test-Path\s+(?:-Path\s+)?'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"regcheck:{normalize_reg_path(m.group(1))}"

    # ------------------------------------------------------------------ #
    # 7. Get-LocalUser -Name 'name'
    # ------------------------------------------------------------------ #
    m = re.search(r"Get-LocalUser\s+-Name\s+'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"account:{m.group(1).lower()}"

    # ------------------------------------------------------------------ #
    # 8. Built-in administrator (SID S-1-5-*-500)
    # ------------------------------------------------------------------ #
    if "S-1-5-*-500" in s:
        return "account:builtin_administrator"

    # ------------------------------------------------------------------ #
    # 9. AnonymousNameLookup (LSA anonymous SID)
    # ------------------------------------------------------------------ #
    if "AnonymousNameLookup" in s:
        return "lsa:anonymousnamelookup"

    # ------------------------------------------------------------------ #
    # 10. WMI policy
    # ------------------------------------------------------------------ #
    m = re.search(r"Get-WmiObject\s+-Namespace\s+'([^']+)'\s+-Query\s+'([^']+)'", s, re.IGNORECASE)
    if m:
        return f"wmi:{m.group(1).lower()}|{m.group(2).lower()}"

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
        elif current_key:
            current_buf.append(line)

    return items

# =============================================================================
# MAIN
# =============================================================================

def _build_integrated(base_path, og_items, all_matched_fps, integrated_path):
    """
    Build a single integrated audit file.

    base_path        – New file used as the base (New[1]).
    og_items         – all parsed OG items.
    all_matched_fps  – fingerprints already covered by ANY New file.
    integrated_path  – destination path for the output file.

    Returns (integrated_path, count) on success, (None, 0) when nothing to add.
    """
    orphaned = [item for item in og_items
                if (get_fingerprint(item) or "") not in all_matched_fps]
    if not orphaned:
        return None, 0

    orphaned_blocks = ["\n".join(item["_raw_lines"])
                       for item in orphaned if item.get("_raw_lines")]
    if not orphaned_blocks:
        return None, 0

    with open(base_path, encoding="utf-8", errors="replace") as f:
        content = f.read()

    then_pattern = re.compile(r'[ \t]*</then>', re.IGNORECASE)
    last_match = None
    for m in then_pattern.finditer(content):
        last_match = m

    if not last_match:
        return None, 0

    insert_pos = last_match.start()
    blocks_text = "\n\n".join(orphaned_blocks) + "\n"
    content = content[:insert_pos] + "\n" + blocks_text + "\n" + content[insert_pos:]

    with open(integrated_path, "w", encoding="utf-8") as f:
        f.write(content)

    return integrated_path, len(orphaned_blocks)


def main():
    # ------------------------------------------------------------------
    # Collect file paths
    # ------------------------------------------------------------------
    og_path = input("Enter OG (reference) file path : ").strip().strip('"').strip("'")
    if not os.path.isfile(og_path):
        print(f"ERROR: OG file not found: {og_path}")
        return

    new_paths = []
    print("Enter New file paths one at a time — blank line when done.")
    while True:
        label = f"  New file {len(new_paths) + 1:<22}"
        p = input(f"{label}: ").strip().strip('"').strip("'")
        if not p:
            break
        if not os.path.isfile(p):
            print(f"  ERROR: file not found: {p}")
            continue
        new_paths.append(p)

    if not new_paths:
        print("No New files entered — nothing to compare.")
        return

    # ------------------------------------------------------------------
    # Parse all files
    # ------------------------------------------------------------------
    print(f"\nParsing OG file  : {og_path}")
    og_items = parse_custom_items(og_path)
    print(f"  {len(og_items)} active items found")

    new_items_list = []
    for np in new_paths:
        print(f"Parsing New file : {np}")
        items = parse_custom_items(np)
        print(f"  {len(items)} active items found")
        new_items_list.append(items)

    # ------------------------------------------------------------------
    # Build OG fingerprint map
    # ------------------------------------------------------------------
    og_fp_map = {}
    og_no_fp  = []
    for item in og_items:
        fp = get_fingerprint(item)
        if fp:
            og_fp_map.setdefault(fp, []).append(item)
        else:
            og_no_fp.append(item)

    print(f"\n  {len(og_fp_map)} unique OG fingerprints  "
          f"({len(og_no_fp)} OG item(s) could not be fingerprinted)")

    # ------------------------------------------------------------------
    # Per-New-file: duplicates vs OG + per-file matched fingerprint sets
    # ------------------------------------------------------------------
    all_duplicates     = []    # combined across all New files
    per_new_no_fp      = []    # int per new file
    per_new_matched    = []    # set of matched OG fps, one per New file
    all_matched_og_fps = set()

    for idx, new_items in enumerate(new_items_list):
        new_no_fp      = 0
        seen_fps       = set()
        matched_og_fps = set()

        for new_item in new_items:
            fp = get_fingerprint(new_item)
            if not fp:
                new_no_fp += 1
                continue
            if fp not in og_fp_map:
                continue
            matched_og_fps.add(fp)
            all_matched_og_fps.add(fp)
            new_desc = new_item.get("description", "(no description)").strip().strip('"')
            for og_item in og_fp_map[fp]:
                og_desc  = og_item.get("description", "(no description)").strip().strip('"')
                pair_key = (fp, og_desc, new_desc, idx)
                if pair_key in seen_fps:
                    continue
                seen_fps.add(pair_key)
                all_duplicates.append({
                    "fp":       fp,
                    "og_desc":  og_desc,
                    "new_desc": new_desc,
                    "new_idx":  idx,      # 0-based index into new_paths
                })

        per_new_no_fp.append(new_no_fp)
        per_new_matched.append(matched_og_fps)

    # ------------------------------------------------------------------
    # Per-New-file orphaned OG items (in OG but not in THIS New file)
    # ------------------------------------------------------------------
    per_new_orphaned = []
    for matched in per_new_matched:
        orphaned = [item for item in og_items
                    if (get_fingerprint(item) or "") not in matched]
        per_new_orphaned.append(orphaned)

    # ------------------------------------------------------------------
    # Cross-New duplicates (fingerprint in 2+ New files, regardless of OG)
    # ------------------------------------------------------------------
    new_fp_maps = []
    for new_items in new_items_list:
        m = {}
        for item in new_items:
            fp = get_fingerprint(item)
            if fp:
                m.setdefault(fp, []).append(item)
        new_fp_maps.append(m)

    all_new_fps = set().union(*[m.keys() for m in new_fp_maps])
    cross_new   = []
    seen_cross  = set()
    for fp in sorted(all_new_fps):
        present_in = [i for i, m in enumerate(new_fp_maps) if fp in m]
        if len(present_in) < 2 or fp in seen_cross:
            continue
        seen_cross.add(fp)
        files_info = []
        for i in present_in:
            for item in new_fp_maps[i][fp]:
                desc = item.get("description", "(no description)").strip().strip('"')
                files_info.append({"idx": i, "desc": desc})
        cross_new.append({"fp": fp, "files": files_info})

    # ------------------------------------------------------------------
    # Write comparison report
    # ------------------------------------------------------------------
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    og_base  = os.path.splitext(os.path.basename(og_path))[0]
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts_safe  = datetime.now().strftime("%Y%m%d-%H%M%S")
    sep      = "=" * 79
    n_new    = len(new_paths)

    if n_new == 1:
        new_base = os.path.splitext(os.path.basename(new_paths[0]))[0]
        outfile  = os.path.join(OUTPUT_DIR, f"{new_base}-vs-{og_base}-duplicates.txt")
    else:
        outfile  = os.path.join(OUTPUT_DIR, f"{og_base}-{n_new}files-comparison-{ts_safe}.txt")

    with open(outfile, "w", encoding="utf-8") as f:

        # Header
        f.write(f"{sep}\n")
        f.write("AUDIT FILE COMPARISON REPORT\n")
        f.write(f"Generated : {ts}\n")
        f.write(f"{sep}\n\n")

        # File summary
        f.write(f"OG File  [0] : {og_path}\n")
        f.write(f"             : {len(og_items)} active items  |  "
                f"{len(og_fp_map)} unique fingerprints\n\n")
        for i, np in enumerate(new_paths):
            f.write(f"New File [{i+1}] : {np}\n")
            f.write(f"             : {len(new_items_list[i])} active items\n\n")

        # ------------------------------------------------------------------
        # Combined duplicates section
        # ------------------------------------------------------------------
        no_fp_total = sum(per_new_no_fp)
        f.write(f"{sep}\n")
        f.write("DUPLICATES  (New items whose check matches an OG check)\n")
        f.write(f"Total : {len(all_duplicates)}\n")
        if no_fp_total:
            f.write(f"(New items without fingerprint : {no_fp_total})\n")
        f.write(f"{sep}\n\n")

        if not all_duplicates:
            f.write("No duplicates found.\n\n")
        else:
            for j, d in enumerate(all_duplicates, 1):
                label = f"New[{d['new_idx']+1}]" if n_new > 1 else "New"
                f.write(f"{j:>4}.  OG      : \"{d['og_desc']}\"\n")
                f.write(f"        {label:<7} : \"{d['new_desc']}\"\n")
                f.write(f"        Key     : {d['fp']}\n\n")

        # ------------------------------------------------------------------
        # Cross-New duplicates (only when ≥ 2 New files)
        # ------------------------------------------------------------------
        if n_new >= 2:
            f.write(f"{sep}\n")
            f.write("CROSS-NEW DUPLICATES  (same check appears in 2+ New files)\n")
            f.write(f"Total : {len(cross_new)}\n")
            f.write(f"{sep}\n\n")
            if not cross_new:
                f.write("No cross-New duplicates found.\n\n")
            else:
                for j, entry in enumerate(cross_new, 1):
                    f.write(f"{j:>4}.  Key : {entry['fp']}\n")
                    for fi in entry["files"]:
                        f.write(f"        New[{fi['idx']+1}] : \"{fi['desc']}\"\n")
                    f.write("\n")

        # ------------------------------------------------------------------
        # Per-New-file orphaned OG sections
        # ------------------------------------------------------------------
        for i, (np, orphaned) in enumerate(zip(new_paths, per_new_orphaned)):
            new_base_i = os.path.splitext(os.path.basename(np))[0]
            label      = f"New[{i+1}]" if n_new > 1 else "New"
            f.write(f"{sep}\n")
            f.write(f"ORPHANED OG ITEMS for {label}  "
                    f"(present in OG, not found in {new_base_i})\n")
            f.write(f"Total : {len(orphaned)}\n")
            f.write(f"{sep}\n\n")
            if not orphaned:
                f.write("No orphaned items.\n\n")
            else:
                for j, item in enumerate(orphaned, 1):
                    desc = item.get("description", "(no description)").strip().strip('"')
                    fp   = get_fingerprint(item) or "(no fingerprint)"
                    f.write(f"{j:>4}.  \"{desc}\"\n")
                    f.write(f"        Key : {fp}\n\n")

        f.write(f"{sep}\n")
        f.write(f"End of report  —  {ts}\n")

    print(f"\nReport written to:\n  {outfile}")

    # ------------------------------------------------------------------
    # Build a single _Integrated.audit
    # New[1] is the base; OG items not found in ANY New file are appended.
    # ------------------------------------------------------------------
    new_base_0       = os.path.splitext(os.path.basename(new_paths[0]))[0]
    integrated_path  = os.path.join(OUTPUT_DIR, f"{new_base_0}_Integrated.audit")

    int_path, count = _build_integrated(
        new_paths[0], og_items, all_matched_og_fps, integrated_path
    )
    if int_path:
        print(f"\nIntegrated file written to:\n  {int_path}")
        print(f"  (base: New[1], {count} orphaned OG block(s) appended)")
    else:
        print("\nNo orphaned OG items across all New files — _Integrated file not needed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
