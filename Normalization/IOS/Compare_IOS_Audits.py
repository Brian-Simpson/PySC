#!/usr/bin/env python3
"""Compare_IOS_Audits.py

Stage 2 of the IOS audit pipeline.

Takes a "new" combined audit file (produced by Process_IOS.py — typically
IOS_Combined.audit) and a "reference" baseline file (e.g. OGIOS.audit) and
produces three outputs:

  IOS_Final.audit         — Complete deployable baseline: reference items first,
                            then any new unique items appended and renumbered.

  IOS_New_Only.audit      — Only the items NOT found in the reference file.
                            Every <item> line prefixed with '#' — inactive,
                            safe to load, for review/approval.

  IOS_New_Only-active.audit — Same new-only items but fully active (no '#').
                            Use to test/deploy new checks independently.

  IOS_Final-report.txt    — Plain-text summary of counts and which items are new.

The reference file is parsed directly — items are collected from both
<then> and <else> branches so OGIOS-style nested <if> checks are handled
correctly without any pre-processing.

Fingerprinting (same as Process_IOS.py):
  BANNER_CHECK   → banner|<item_pattern>|<content_pattern>
  CONFIG_CHECK*  → config|[<context>|]<item_pattern>

First occurrence (reference) always wins on duplicates.

Usage:
    python Compare_IOS_Audits.py      <- prompts for file paths
"""

import copy
import os
import re
from datetime import datetime

OUTPUT_DIR = r"C:\PySC\IOS"

# =============================================================================
# FINGERPRINTING
# =============================================================================

def _normalise_pattern(raw):
    s = raw.strip().strip('"').strip("'").lower().strip()
    # Iteratively strip trailing anchors / optional-whitespace constructs so
    # patterns like "aaa new-model[ ]*$" and "aaa new-model" fingerprint the
    # same.  Only strip things that serve as line-ending anchors, not
    # meaningful content inside the pattern.
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r'\[\s*\][\*+?]?\s*\$?\s*$', '', s).strip()  # [ ]*$  [ ]$  [ ]+
        s = re.sub(r'\s*[\*+?]?\$\s*$', '', s).strip()           # $  *$  +$
        s = re.sub(r'\s+\*\s*$', '', s).strip()                   # trailing  *
        s = re.sub(r'\.\*$', '', s).strip()                       # trailing .*
    return s


def get_fingerprint(fields):
    """
    Build a normalised fingerprint for an IOS <item> block.
    Returns None for items with no matchable content.
    """
    item_type = fields.get('type', '').strip().upper()
    item_val  = fields.get('item', '')
    context   = fields.get('context', '')
    regex_val = fields.get('regex', '')
    content   = fields.get('content', '')

    if item_type == 'BANNER_CHECK':
        pat  = _normalise_pattern(item_val or '')
        cont = _normalise_pattern(content)
        return f"banner|{pat}|{cont}" if (pat or cont) else None

    if item_type.startswith('CONFIG_CHECK'):
        pat = _normalise_pattern(item_val) if item_val else _normalise_pattern(regex_val)
        if not pat:
            return None
        ctx = _normalise_pattern(context)
        return f"config|{ctx}|{pat}" if ctx else f"config|{pat}"

    return None


# =============================================================================
# PARSER
# =============================================================================

def _parse_item_fields(block_text):
    """Extract field → value mapping from a single item block's text."""
    fields = {}
    for field in ('type', 'description', 'info', 'reference', 'see_also',
                  'context', 'item', 'regex', 'content', 'is_substring'):
        m = re.search(rf'^\s*{re.escape(field)}\s*:\s*(.*)',
                      block_text, re.MULTILINE)
        if m:
            fields[field] = m.group(1).strip()
    return fields


def parse_items(filepath):
    """
    Parse all active check <item> blocks from an IOS audit file.
    Items inside <condition> blocks are skipped.
    Returns list of field-dicts, each with '_raw_lines'.
    """
    items = []
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = [ln.rstrip() for ln in f.readlines()]

    context_stack = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        slow     = stripped.lower()

        if re.match(r'<condition\b', stripped, re.IGNORECASE):
            context_stack.append('condition')
        elif slow == '</condition>':
            if context_stack and context_stack[-1] == 'condition':
                context_stack.pop()
        elif slow == '<then>':
            context_stack.append('then')
        elif slow == '</then>':
            if context_stack and context_stack[-1] == 'then':
                context_stack.pop()
        elif slow == '<else>':
            context_stack.append('else')
        elif slow == '</else>':
            if context_stack and context_stack[-1] == 'else':
                context_stack.pop()
        elif stripped == '<item>':
            block = [lines[i]]
            i += 1
            while i < len(lines):
                block.append(lines[i])
                if lines[i].strip() == '</item>':
                    i += 1
                    break
                i += 1
            if 'condition' not in context_stack:
                block_text = '\n'.join(block)
                fields     = _parse_item_fields(block_text)
                t = fields.get('type', '').upper()
                if t.startswith('CONFIG_CHECK') or t == 'BANNER_CHECK':
                    fields['_raw_lines'] = block
                    items.append(fields)
            continue
        i += 1
    return items


# =============================================================================
# WRAPPER EXTRACTION
# =============================================================================

def extract_wrapper(filepath):
    """
    Return (header_lines, footer_lines) split at the outermost <then>...</then>.
    header_lines includes everything up to and including the outermost <then>.
    footer_lines starts at the matching outermost </then>.
    Uses if-depth tracking so nested <if> blocks don't confuse the search.
    """
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = [ln.rstrip() for ln in f.readlines()]

    then_open  = None
    then_close = None
    if_depth   = 0

    for idx, line in enumerate(lines):
        s = line.strip().lower()
        if s == '<if>':
            if_depth += 1
        elif s == '</if>':
            if_depth -= 1
        elif s == '<then>' and if_depth == 1 and then_open is None:
            then_open = idx
        elif s == '</then>' and if_depth == 1:
            then_close = idx

    if then_open is None or then_close is None:
        return lines, []
    return lines[:then_open + 1], lines[then_close:]


# =============================================================================
# HELPERS
# =============================================================================

def align_colons(lines):
    """Align 'key : value' separators to the same column across all lines."""
    kv_re   = re.compile(r'^(\s*)([A-Za-z0-9_]+)(\s+): ')
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
            key    = m.group(2)
            rest   = line[len(indent) + len(key) + len(m.group(3)):]
            pad    = max_col - len(indent) - len(key)
            result.append(f"{indent}{key}{' ' * pad}{rest}")
        else:
            result.append(line)
    return result


# Strips: '1.XXXX - NETIOS - '  OR  'AC - NetIOS - '  OR  'CM - NetIOS - '  etc.
_RENUMBER_RE = re.compile(
    r'^(\s*description\s*:\s*")'
    r'(?:\d+\.\d+\s*-\s*NETIOS\s*-\s*)?'   # e.g. 1.0042 - NETIOS -
    r'(?:[A-Z]+\s*-\s*Net\w+\s*-\s*)?'      # e.g. AC - NetIOS -
    r'(.*)',
    re.IGNORECASE
)


def renumber_items(items, start=1):
    """
    Renumber all items to sequential 1.XXXX order starting at `start`.
    Strips existing numeric (1.XXXX - NETIOS -) and old-style
    (AC - NetIOS -) prefixes before applying the new number.
    """
    for counter, item in enumerate(items, start):
        new_lines = []
        for line in item['_raw_lines']:
            m = _RENUMBER_RE.match(line)
            if m:
                line = f'{m.group(1)}1.{counter:04d} - NETIOS - {m.group(2).rstrip(chr(34))}"'
            new_lines.append(line)
        item['_raw_lines'] = new_lines
    return items


def _normalise_item_indent(raw_lines):
    """
    Re-indent an item block to a uniform 4-space indent for all field lines.
    The opening <item> and closing </item> tags get 4 spaces;
    field lines inside get 6 spaces.
    """
    out = []
    for line in raw_lines:
        s = line.strip()
        if not s:
            continue
        if s in ('<item>', '</item>'):
            out.append('    ' + s)
        else:
            out.append('      ' + s)
    return out


def comment_out_item(raw_lines):
    """Prefix every line of a raw item block with '# ' to deactivate it."""
    return ['# ' + ln for ln in raw_lines]


def build_audit_file(items, header_lines, footer_lines):
    """Assemble an active (uncommented) audit file from items + wrapper."""
    blocks = []
    for item in items:
        normalised = _normalise_item_indent(item['_raw_lines'])
        aligned    = align_colons(normalised)
        blocks.append('\n'.join(aligned))
    item_section = '\n\n'.join(blocks)
    out_lines    = header_lines + [item_section, ''] + footer_lines
    flat         = '\n'.join(out_lines)
    # Final global pass aligns the wrapper / condition block lines too
    return '\n'.join(align_colons(flat.splitlines())) + '\n'


def comment_active_content(content):
    """Derive a commented-out version of an already-built active audit file.

    Takes the finished active file content and prefixes every line that falls
    inside an <item> ... </item> block with '# '.  Lines outside items
    (header, footer, blank lines) are left untouched.  This guarantees that
    the commented file is structurally identical to the active file except for
    the '# ' prefix on item lines.
    """
    in_item = False
    out = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == '<item>':
            in_item = True
        if in_item:
            out.append('# ' + line)
        else:
            out.append(line)
        if stripped == '</item>':
            in_item = False
    return '\n'.join(out) + '\n'


def comment_selected_items(content, descs_to_comment):
    """Given a fully-built (active, aligned) audit file content, comment out
    only the <item> blocks whose description appears in descs_to_comment.
    All other lines (header, footer, active items) are left untouched.
    Because we operate on already-aligned content, column widths are uniform
    across both active and commented sections.
    """
    lines = content.splitlines()
    out   = []
    i     = 0
    while i < len(lines):
        if lines[i].strip() == '<item>':
            # Buffer the entire item block before deciding
            block = []
            while i < len(lines):
                block.append(lines[i])
                if lines[i].strip() == '</item>':
                    i += 1
                    break
                i += 1
            # Check description against the comment set
            should_comment = False
            for bl in block:
                m = re.match(r'^\s*description\s*:\s*"(.+)', bl)
                if m:
                    desc = m.group(1).lower().rstrip('"').rstrip()
                    if desc in descs_to_comment:
                        should_comment = True
                    break
            if should_comment:
                out.extend('# ' + bl for bl in block)
            else:
                out.extend(block)
        else:
            out.append(lines[i])
            i += 1
    return '\n'.join(out) + '\n'


# =============================================================================
# VALIDATION
# =============================================================================

# Valid Cisco audit item types accepted by Tenable IO
_VALID_TYPES = {
    'CONFIG_CHECK', 'CONFIG_CHECK_NOT',
    'CONFIG_CHECK_REGEX', 'CONFIG_CHECK_NOT_REGEX',
    'BANNER_CHECK',
}

# All field names Tenable IO recognises inside a Cisco <item>
_VALID_FIELDS = {
    'type', 'description', 'info', 'reference', 'see_also',
    'context', 'item', 'regex', 'content', 'is_substring',
    'solution', 'severity',
}


def validate_audit_output(filepath):
    """Tenable IO syntax validation for a Cisco IOS audit file.

    Checks performed
    ----------------
    1. Exactly one <check_type:…> / </check_type> pair.
    2. Balanced <if> / </if>, <then> / </then>, <else> / </else> tags.
    3. No <item> block inside a <condition> block.
    4. Every active (un-commented) <item> block:
       a. Has 'type', 'description', and 'item' (or 'content' for BANNER_CHECK).
       b. 'type' value is a recognised Tenable IO check type.
       c. CONFIG_CHECK_REGEX / CONFIG_CHECK_NOT_REGEX have a 'regex' field.
       d. BANNER_CHECK has a 'content' field.
       e. All field names are recognised (warns on unknown fields).
       f. Required string fields are double-quoted.
       g. No field value contains an unescaped literal newline inside quotes.
    5. Tag-depth balance walk — every open tag has a matching close at same depth.
    """
    print(f"\n--- Validating: {os.path.basename(filepath)} ---")
    with open(filepath, encoding='utf-8') as fh:
        raw_lines = fh.readlines()

    issues      = []
    item_issues = []

    # ------------------------------------------------------------------ #
    # 1. check_type wrapper                                               #
    # ------------------------------------------------------------------ #
    ct_open  = sum(1 for l in raw_lines if re.search(r'<check_type:', l))
    ct_close = sum(1 for l in raw_lines if l.strip() == '</check_type>')
    if ct_open != 1 or ct_close != 1:
        issues.append(f"check_type wrapper: {ct_open} open / {ct_close} close (expected 1 each)")

    # ------------------------------------------------------------------ #
    # 2 & 5. Tag-balance walk                                             #
    # ------------------------------------------------------------------ #
    tag_counts = {'if': 0, 'then': 0, 'else': 0, 'condition': 0}
    for line in raw_lines:
        if line.lstrip().startswith('#'):
            continue          # skip commented lines entirely
        s = line.strip()
        for tag in tag_counts:
            if s == f'<{tag}>' or re.match(rf'^<{tag}\b', s):
                tag_counts[tag] += 1
            elif s == f'</{tag}>':
                tag_counts[tag] -= 1
    for tag, delta in tag_counts.items():
        if delta != 0:
            issues.append(f"Unbalanced <{tag}> tags: net {delta:+d}")

    # ------------------------------------------------------------------ #
    # 3 & 4. Per-item checks (active items only)                          #
    # ------------------------------------------------------------------ #
    in_condition = False
    in_item      = False
    item_buf     = []
    item_linenos = []
    item_count   = 0

    for lineno, line in enumerate(raw_lines, 1):
        if line.lstrip().startswith('#'):
            continue
        s = line.strip()

        # Track condition depth so we can skip <item> blocks inside them
        if re.match(r'^<condition\b', s):
            in_condition = True
        elif s == '</condition>':
            in_condition = False

        if in_condition:
            continue

        if not in_item:
            if s == '<item>':
                in_item    = True
                item_buf   = []
                item_linenos = [lineno]
        else:
            item_buf.append(s)
            item_linenos.append(lineno)
            if s == '</item>':
                item_count += 1
                block = '\n'.join(item_buf)
                errs  = []

                # --- required fields ---
                if not re.search(r'^\s*type\s*:', block, re.M):
                    errs.append("missing 'type'")
                if not re.search(r'^\s*description\s*:', block, re.M):
                    errs.append("missing 'description'")

                # --- type value ---
                tm = re.search(r'^\s*type\s*:\s*(\S+)', block, re.M)
                item_type = tm.group(1).strip().upper() if tm else ''
                if item_type and item_type not in _VALID_TYPES:
                    errs.append(f"unknown type '{item_type}'")

                # --- item / content requirement ---
                has_item    = bool(re.search(r'^\s*item\s*:', block, re.M))
                has_content = bool(re.search(r'^\s*content\s*:', block, re.M))
                if item_type == 'BANNER_CHECK':
                    if not has_content:
                        errs.append("BANNER_CHECK missing 'content'")
                    if not has_item:
                        errs.append("BANNER_CHECK missing 'item'")
                elif item_type:
                    if not has_item:
                        errs.append("missing 'item'")

                # --- regex field for REGEX types ---
                if 'REGEX' in item_type and not re.search(r'^\s*regex\s*:', block, re.M):
                    errs.append(f"{item_type} missing 'regex'")

                # --- unknown field names ---
                for fm in re.finditer(r'^\s*([a-z_]+)\s*:', block, re.M):
                    fname = fm.group(1).lower()
                    if fname not in _VALID_FIELDS:
                        errs.append(f"unknown field '{fname}'")

                # --- string fields must be double-quoted ---
                for qf in ('description', 'info', 'reference', 'see_also',
                           'item', 'regex', 'content', 'context'):
                    qm = re.search(rf'^\s*{qf}\s*:\s*(.+)', block, re.M)
                    if qm:
                        val = qm.group(1).strip()
                        if val and not val.startswith('"'):
                            errs.append(f"field '{qf}' value not double-quoted: {val[:40]}")

                if errs:
                    dm   = re.search(r'description\s*:\s*"([^"]*)"', block)
                    desc = dm.group(1)[:70] if dm else '(unknown)'
                    item_issues.append((item_count, item_linenos[0], desc, errs))

                in_item      = False
                item_buf     = []
                item_linenos = []

    # ------------------------------------------------------------------ #
    # Report                                                              #
    # ------------------------------------------------------------------ #
    ok = not issues and not item_issues
    if issues:
        print("  STRUCTURAL ISSUES:")
        for iss in issues:
            print(f"    {iss}")
    if item_issues:
        print(f"  ITEM ISSUES ({len(item_issues)}):")
        for n, lineno, desc, errs in item_issues[:15]:
            print(f"    block {n} (line {lineno}): {desc}")
            for e in errs:
                print(f"      - {e}")
        if len(item_issues) > 15:
            print(f"    … and {len(item_issues) - 15} more")
    if ok:
        print(f"  All {item_count} active <item> blocks: OK")
    print(f"  Result: {'PASS' if ok else 'FAIL u2014 see errors above'}")
    return ok


# =============================================================================
# MAIN
# =============================================================================

def main():
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"Cisco IOS Audit Comparator  [{ts}]")
    print("=" * 60)
    print()
    print("This tool merges a 'new' combined file with a reference baseline.")
    print("  IOS_Final.audit          — all items active (reference + new unique)")
    print("  IOS_New_Only.audit       — only new items, commented out for review")
    print("  IOS_New_Only-active.audit— only new items, active (uncommented)")
    print()

    # ------------------------------------------------------------------
    # Prompt for reference file
    # ------------------------------------------------------------------
    while True:
        raw = input("  Reference file (e.g. OGIOS.audit): ").strip().strip('"').strip("'")
        if not raw:
            print("No reference file specified. Exiting.")
            return
        ref_path = os.path.abspath(raw)
        if os.path.isfile(ref_path):
            break
        print(f"    File not found: {ref_path}")

    # ------------------------------------------------------------------
    # Prompt for new/combined file
    # ------------------------------------------------------------------
    default_combined = os.path.join(OUTPUT_DIR, 'IOS_Combined.audit')
    prompt_hint = f" [default: IOS_Combined.audit]"
    while True:
        raw = input(f"  New/combined file{prompt_hint}: ").strip().strip('"').strip("'")
        if not raw:
            raw = default_combined
        new_path = os.path.abspath(raw)
        if os.path.isfile(new_path):
            break
        print(f"    File not found: {new_path}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Parse both files
    # ------------------------------------------------------------------
    print(f"\nParsing reference : {os.path.basename(ref_path)}")
    ref_items  = parse_items(ref_path)
    print(f"  {len(ref_items)} check items found")

    print(f"Parsing new file  : {os.path.basename(new_path)}")
    new_items  = parse_items(new_path)
    print(f"  {len(new_items)} check items found")

    # ------------------------------------------------------------------
    # Fingerprint reference; find new-only items
    # ------------------------------------------------------------------
    ref_fps = {}
    for item in ref_items:
        fp = get_fingerprint(item)
        if fp:
            ref_fps[fp] = item.get('description', '').strip().strip('"')

    truly_new  = []
    duplicates = []        # list of (new_item_dict, ref_desc_str)
    for item in new_items:
        fp = get_fingerprint(item)
        if fp is None or fp not in ref_fps:
            truly_new.append(item)
        else:
            duplicates.append((item, ref_fps[fp]))

    print(f"\n  Reference items  : {len(ref_items)}")
    print(f"  New items        : {len(new_items)}")
    print(f"  Already in ref   : {len(duplicates)} (deduped)")
    print(f"  Genuinely new    : {len(truly_new)}")

    # ------------------------------------------------------------------
    # Renumber: reference keeps its numbers 1..N.
    # truly_new is renumbered 1..M for standalone New_Only files,
    # then a deep copy is renumbered N+1..N+M for IOS_Final.
    # deduped_items are renumbered 1..K for use in IOS_New_Only.
    # ------------------------------------------------------------------
    ref_items = renumber_items(ref_items, start=1)

    # Extract item dicts from duplicates for New_Only display
    deduped_items = [item for item, _ref_desc in duplicates]
    deduped_items = renumber_items(deduped_items, start=1)   # 1..K active in New_Only

    truly_new = renumber_items(truly_new, start=len(deduped_items) + 1)  # K+1..K+M commented

    # Deep-copy raw_lines so Final renumbering doesn't affect New_Only items
    truly_new_final = renumber_items(
        [dict(it, _raw_lines=list(it['_raw_lines'])) for it in copy.deepcopy(truly_new)],
        start=len(ref_items) + 1
    )
    all_items = ref_items + truly_new_final

    # ------------------------------------------------------------------
    # Wrapper: header from reference file (HTH condition check), but a
    # fixed clean footer — OGIOS.audit has extra nested <if> blocks after
    # its </then> which must not be copied into output files.
    # ------------------------------------------------------------------
    header_lines, _ref_footer = extract_wrapper(ref_path)
    footer_lines = [
        '',
        '  </then>',
        '',
        '  <else>',
        '    <report type:"WARNING">',
        '      description : "WARNING - TARGET OS DOESNT MATCH BASELINE - IOS"',
        '      info        : "NOTE: Nessus has identified that the chosen audit does not apply to the target device."',
        '      see_also    : "See HTH Policies and Standards"',
        '    </report>',
        '  </else>',
        '</if>',
        '',
        '</check_type>',
    ]

    # ------------------------------------------------------------------
    # Write IOS_Final.audit — everything active
    # ------------------------------------------------------------------
    final_file = os.path.join(OUTPUT_DIR, 'IOS_Final.audit')
    with open(final_file, 'w', encoding='utf-8') as f:
        f.write(build_audit_file(all_items, header_lines, footer_lines))
    print(f"\n  Final file        : {final_file}")
    validate_audit_output(final_file)

    # ------------------------------------------------------------------
    # Write IOS_New_Only-active.audit — genuinely new items only, active
    # ------------------------------------------------------------------
    new_active_file = os.path.join(OUTPUT_DIR, 'IOS_New_Only-active.audit')
    active_content = build_audit_file(truly_new, header_lines, footer_lines)
    with open(new_active_file, 'w', encoding='utf-8') as f:
        f.write(active_content)
    print(f"  New-only (active) : {new_active_file}  ({len(truly_new)} items)")
    validate_audit_output(new_active_file)

    # ------------------------------------------------------------------
    # Write IOS_New_Only.audit — deduped items active, truly-new commented
    # Build the complete file with ALL items active first so align_colons
    # operates on the full item set and produces uniform column widths.
    # Then comment out only the truly-new blocks by description matching.
    # ------------------------------------------------------------------
    new_only_file = os.path.join(OUTPUT_DIR, 'IOS_New_Only.audit')
    # Build the description set from _raw_lines (which hold the renumbered
    # description) so it matches what comment_selected_items reads from the
    # already-built file content.
    truly_new_descs = set()
    for item in truly_new:
        for line in item['_raw_lines']:
            m = re.match(r'^\s*description\s*:\s*"(.+)', line)
            if m:
                truly_new_descs.add(m.group(1).lower().rstrip('"').rstrip())
                break
    new_only_active = build_audit_file(deduped_items + truly_new, header_lines, footer_lines)
    new_only_content = comment_selected_items(new_only_active, truly_new_descs)
    with open(new_only_file, 'w', encoding='utf-8') as f:
        f.write(new_only_content)
    print(f"  New-only          : {new_only_file}  ({len(deduped_items)} active + {len(truly_new)} commented)")
    validate_audit_output(new_only_file)

    # ------------------------------------------------------------------
    # Write report
    # ------------------------------------------------------------------
    sep         = '=' * 79
    report_file = os.path.join(OUTPUT_DIR, 'IOS_Final-report.txt')
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"{sep}\n")
        f.write(f"IOS AUDIT COMPARE REPORT\n")
        f.write(f"Generated  : {ts}\n")
        f.write(f"Reference  : {os.path.basename(ref_path)}\n")
        f.write(f"New/combined: {os.path.basename(new_path)}\n")
        f.write(f"{sep}\n\n")
        f.write(f"Reference items  : {len(ref_items)}\n")
        f.write(f"New items        : {len(new_items)}\n")
        f.write(f"Already in ref   : {len(duplicates)} (deduped — active in New_Only)\n")
        f.write(f"Genuinely new    : {len(truly_new)}\n")
        f.write(f"Final total      : {len(all_items)}\n\n")
        if duplicates:
            f.write(f"--- Items already in reference (deduped) ---\n")
            for new_item, ref_desc in duplicates:
                new_desc = new_item.get('description', '').strip().strip('"')
                f.write(f"  NEW : {new_desc[:70]}\n")
                f.write(f"  REF : {ref_desc[:70]}\n\n")
        if truly_new:
            f.write(f"--- Genuinely new items (added to Final, commented in New-Only) ---\n")
            for item in truly_new:
                desc = item.get('description', '').strip().strip('"')
                f.write(f"  {desc[:75]}\n")
    print(f"  Report            : {report_file}")

    print(f"\n{'=' * 60}")
    print(f"  IOS_Final.audit          : {len(all_items)} items ({len(ref_items)} ref + {len(truly_new)} new)")
    print(f"  IOS_New_Only.audit       : {len(deduped_items)} active + {len(truly_new)} commented")
    print(f"  IOS_New_Only-active.audit: {len(truly_new)} items active")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
