#!/usr/bin/env python3
"""Process_IOS.py

Combined pipeline for Cisco IOS audit files:
  Step 1 — Normalize    (fields cleaned, variables applied, descriptions numbered)
  Step 2 — Flatten      (nested if/then/else collapsed to single outer if)
  Step 3 — Align        (colon-align all field separators)

Input:  any Cisco IOS .audit file (CIS or HTH custom)
Output: {base}-normalized.audit  (in OUTPUT_DIR)

Tenable IO / Nessus Cisco check_type compatibility is preserved throughout:
  - <check_type:"Cisco"> wrapper unchanged
  - <item> tags (not <custom_item>)
  - Valid types: CONFIG_CHECK, CONFIG_CHECK_NOT, CONFIG_CHECK_REGEX,
                 CONFIG_CHECK_NOT_REGEX, BANNER_CHECK
  - Outer <if>/<condition>/<then>/<else> OS-detection structure retained
"""

import os
import re
from datetime import datetime

# =============================================================================
# CONFIGURATION
# =============================================================================

OUTPUT_DIR = r"C:\PySC\IOS"

# =============================================================================
# BATCH FILE LIST
# Add absolute paths here to process multiple files without prompting.
# Leave empty to be prompted at runtime.
# =============================================================================
IOS_AUDIT_FILES = [
    # Add absolute paths here for unattended batch runs.
    # Leave empty to be prompted at runtime.
]

# Fields to drop silently from source items
IGNORED_KEYS = {"solution"}

SEE_ALSO_REPLACEMENT = "See HTH Policies and Standards"

# HTH baseline variable values — these OVERRIDE any defaults found in the
# audit file's #<variables> block.  All $VAR$ / @VAR@ placeholders in the
# source file are substituted with these values.
BASELINE_VARS = {
    "BANNER_EXEC":    "All unauthorized activity is monitored and logged.",
    "BANNER_LOGIN":   "All unauthorized activity is monitored and logged.",
    "BANNER_MOTD":    "All unauthorized activity is monitored and logged.",
    "VTY_ACL":        "100",
    "SNMP_ACL":       "1",
    "SNMP_TRAP_HOST": r"192\.168\.0\.2",
    "LOGGING_HOST_IP":r"192\.168\.2\.1",
    "NTP_SERVER":     r"192\.168\.3\.1",
}

# =============================================================================
# SHARED HELPERS
# =============================================================================

def resolve_variables(text, variables):
    """Substitute $VAR$ / @VAR@ / $VAR placeholders."""
    for k, v in variables.items():
        text = text.replace(f"${k}$", v)
        text = text.replace(f"@{k}@", v)
        text = text.replace(f"${k}",  v)
    return text


def extract_file_variables(lines):
    """
    Parse the #<variables> XML comment block at the top of a CIS audit file.
    Lines in that block look like:
        #  <name>BANNER_EXEC</name>
        #  <default>All unauthorized activity...</default>

    Returns a dict of variable_name -> default_value extracted from the file.
    BASELINE_VARS will be merged on top of these in merge_variables().
    """
    variables = {}
    in_vars   = False
    in_var    = False
    name      = None
    default   = None

    for line in lines:
        # Strip leading '#' comment marker and surrounding whitespace
        s = line.strip()
        if s.startswith('#'):
            s = s[1:].strip()

        if '<variables>' in s:
            in_vars = True
            continue
        if '</variables>' in s:
            break
        if not in_vars:
            continue

        if '<variable>' in s:
            in_var  = True
            name    = None
            default = None
            continue
        if '</variable>' in s:
            if name and default is not None:
                variables[name] = default
            in_var = False
            continue

        if in_var:
            m = re.match(r'<name>(.*?)</name>', s)
            if m:
                name = m.group(1).strip()
            m = re.match(r'<default>(.*?)</default>', s)
            if m:
                default = m.group(1).strip()

    return variables


def merge_variables(file_vars, baseline_vars):
    """
    Merge variables extracted from the audit file with BASELINE_VARS.
    BASELINE_VARS take precedence — they represent HTH's configured values.
    File defaults fill in any variables not covered by BASELINE_VARS.
    """
    merged = dict(file_vars)      # start with file defaults
    merged.update(baseline_vars)  # HTH baseline overrides
    return merged


# Patterns for stripping existing description prefixes
_CIS_PREFIX_RE    = re.compile(r'^[0-9]+(?:\.[0-9]+)*\s+')
_NETIOS_PREFIX_RE = re.compile(r'^1\.\d{4}\s*-\s*NETIOS\s*-\s*', re.IGNORECASE)


def clean_description(raw):
    """Strip CIS benchmark numbering or existing NETIOS prefix."""
    s = raw.strip().strip('"').strip("'")
    s = _CIS_PREFIX_RE.sub('', s)
    s = _NETIOS_PREFIX_RE.sub('', s).strip()
    return s


def normalize_info(raw):
    """Return the first sentence of the info value as a quoted string."""
    if not raw:
        return None
    s = raw.strip().lstrip('"').lstrip("'").strip()
    if not s:
        return None
    # Take text up to first period
    m = re.match(r"([^.]+\.)", s)
    if m:
        sentence = m.group(1).strip().rstrip('"').rstrip("'")
    else:
        sentence = s.split('\n')[0].strip().strip('"').strip("'")
    if not sentence:
        return None
    return f'"{sentence}"'


def normalize_reference(raw):
    """
    Extract NIST 800-53r5 control IDs from a Tenable reference string and
    return them as: "NIST 800-53r5|XX-Y XX-Z ..."
    Falls back to CM-6 if nothing matches.
    """
    if not raw:
        return '"NIST 800-53r5|CM-6"'
    s = raw.strip().strip('"').strip("'")
    # CIS reference strings contain "800-53r5|AC-2(1),..."
    controls = re.findall(r'800-53r5\|([A-Z]{2}-\d+(?:\(\d+\))?)', s)
    if not controls:
        controls = re.findall(r'800-53\|([A-Z]{2}-\d+(?:\(\d+\))?)', s)
    if not controls:
        # Try "NIST 800-53r5|XX-Y YY-Z" space-separated form
        m = re.search(r'NIST 800-53r5\|([\w()| -]+)', s)
        if m:
            controls = m.group(1).split()
    if not controls:
        return '"NIST 800-53r5|CM-6"'
    seen = set()
    unique = [c for c in controls if not (c in seen or seen.add(c))]
    return '"NIST 800-53r5|' + ' '.join(unique) + '"'


def _get_field_line(block_text, field_name):
    """
    Return the value on the same line as 'field_name :' (single-line extraction).
    Works correctly for all IOS single-line fields.
    For multi-line fields (info, reference) this returns just the first line,
    which is sufficient for our normalization purposes.
    """
    m = re.search(
        rf'^\s*{re.escape(field_name)}\s*:\s*(.*)',
        block_text, re.MULTILINE
    )
    return m.group(1).strip() if m else None


def align_colons(lines):
    """Align 'key : value' separators to the same column across all lines."""
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
            key    = m.group(2)
            rest   = line[len(indent) + len(key) + len(m.group(3)):]
            pad    = max_col - len(indent) - len(key)
            result.append(f"{indent}{key}{' ' * pad}{rest}")
        else:
            result.append(line)
    return result


# =============================================================================
# ITEM BLOCK NORMALIZER
# =============================================================================

def normalize_item_block(block_lines, counter):
    """
    Normalize a single <item>...</item> block and return new lines.
    Preserves the tag indentation level of the original block.
    counter: integer used for the 1.XXXX description number.
    """
    block_text = '\n'.join(block_lines)

    item_type    = _get_field_line(block_text, 'type')
    if not item_type:
        return block_lines          # malformed – pass through unchanged

    desc_raw     = _get_field_line(block_text, 'description') or ''
    info_raw     = _get_field_line(block_text, 'info')
    reference_raw= _get_field_line(block_text, 'reference')
    context_raw  = _get_field_line(block_text, 'context')
    item_raw     = _get_field_line(block_text, 'item')
    regex_raw    = _get_field_line(block_text, 'regex')
    content_raw  = _get_field_line(block_text, 'content')
    is_sub_raw   = _get_field_line(block_text, 'is_substring')

    # Preserve the indentation level of the opening tag
    tag_line   = block_lines[0] if block_lines else ''
    tag_indent = len(tag_line) - len(tag_line.lstrip())
    ti = ' ' * tag_indent           # tag indent
    fi = ' ' * (tag_indent + 2)    # field indent

    # Normalise fields
    desc_clean = clean_description(desc_raw)
    new_desc   = f'"1.{counter:04d} - NETIOS - {desc_clean}"'
    new_info   = normalize_info(info_raw)
    new_ref    = normalize_reference(reference_raw)
    new_see    = f'"{SEE_ALSO_REPLACEMENT}"'

    # Reconstruct — the 6 standard fields are ALWAYS present.
    # Optional fields (context, regex, content, is_substring) appear only
    # when they carry a value.
    result = [f'{ti}<item>']
    result.append(f'{fi}type        : {item_type}')
    result.append(f'{fi}description : {new_desc}')
    result.append(f'{fi}info        : {new_info if new_info else ""}')
    result.append(f'{fi}reference   : {new_ref}')
    result.append(f'{fi}see_also    : {new_see}')
    if context_raw:
        result.append(f'{fi}context     : {context_raw}')
    # item field always present (required by Tenable Cisco check engine)
    result.append(f'{fi}item        : {item_raw if item_raw else ""}')
    if regex_raw:
        result.append(f'{fi}regex       : {regex_raw}')
    if content_raw:
        result.append(f'{fi}content     : {content_raw}')
    if is_sub_raw:
        result.append(f'{fi}is_substring: {is_sub_raw}')
    result.append(f'{ti}</item>')

    return result


# =============================================================================
# STEP 1 — NORMALIZE
# =============================================================================

def run_normalize(infile, baseline_vars):
    """
    Parse the audit file, extract its #<variables> block, merge with
    baseline_vars, substitute placeholders, normalise every check <item>
    block (those NOT inside a <condition> block), and write the result to
    {base}-normalized.audit.  Returns (outfile, num_items).
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base    = os.path.splitext(os.path.basename(infile))[0]
    outfile = os.path.join(OUTPUT_DIR, f"{base}-normalized.audit")

    with open(infile, encoding='utf-8', errors='replace') as f:
        raw_lines   = f.readlines()
        raw_content = ''.join(raw_lines)

    # Extract variables declared in the file, then overlay HTH baselines
    file_vars = extract_file_variables([l.rstrip() for l in raw_lines])
    variables = merge_variables(file_vars, baseline_vars)
    if file_vars:
        new_vars = [k for k in file_vars if k not in baseline_vars]
        print(f"  File variables   : {len(file_vars)} found"
              + (f", {len(new_vars)} not in baseline ({', '.join(new_vars)})" if new_vars else ", all covered by baseline"))

    raw_content = resolve_variables(raw_content, variables)
    lines = raw_content.splitlines()

    result          = []
    counter         = 1
    context_stack   = []   # elements: 'condition' | 'then' | 'else'
    i               = 0

    while i < len(lines):
        line    = lines[i]
        stripped = line.strip()
        slow    = stripped.lower()

        # ---- Strip source comment lines (e.g. #<ui_metadata> / #<variables> blocks) ----
        if stripped.startswith('#'):
            i += 1
            continue

        # ---- Track structural depth ----
        if re.match(r'<condition\b', stripped, re.IGNORECASE):
            context_stack.append('condition')
            result.append(line)
            i += 1
            continue

        if slow == '</condition>':
            if context_stack and context_stack[-1] == 'condition':
                context_stack.pop()
            result.append(line)
            i += 1
            continue

        if slow == '<then>':
            context_stack.append('then')
            result.append(line)
            i += 1
            continue

        if slow == '</then>':
            if context_stack and context_stack[-1] == 'then':
                context_stack.pop()
            result.append(line)
            i += 1
            continue

        if slow == '<else>':
            context_stack.append('else')
            result.append(line)
            i += 1
            continue

        if slow == '</else>':
            if context_stack and context_stack[-1] == 'else':
                context_stack.pop()
            result.append(line)
            i += 1
            continue

        # ---- Collect <item>...</item> block ----
        if stripped == '<item>':
            block = [line]
            i += 1
            while i < len(lines):
                block.append(lines[i])
                if lines[i].strip() == '</item>':
                    i += 1
                    break
                i += 1

            in_condition = 'condition' in context_stack
            if in_condition:
                result.extend(block)
            else:
                result.extend(normalize_item_block(block, counter))
                counter += 1
            continue

        result.append(line)
        i += 1

    num_items = counter - 1

    # Insert processing header just before <check_type:
    ts     = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = [
        f'# Processed by Process_IOS.py  [{ts}]',
        f'# Source  : {os.path.basename(infile)}',
        f'# Items   : {num_items}',
        '',
    ]
    insert_at = 0
    for idx, ln in enumerate(result):
        if ln.strip() and not ln.strip().startswith('#'):
            insert_at = idx
            break
    final = result[:insert_at] + header + result[insert_at:]

    final = align_colons(final)

    # Force every see_also line (in any block, including <report>) to the
    # HTH standard value — catches CIS workbench URLs and any other remnants.
    _see_also_re = re.compile(r'^(\s*see_also\s*:\s*).*$')
    final = [
        _see_also_re.sub(lambda m: m.group(1) + f'"{SEE_ALSO_REPLACEMENT}"', ln)
        if re.match(r'\s*see_also\s*:', ln) else ln
        for ln in final
    ]

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final) + '\n')

    print(f"  Items normalized : {num_items}")
    print(f"  Output           : {outfile}")
    return outfile, num_items


# =============================================================================
# STEP 2 — FLATTEN NESTED IFS
# =============================================================================

def _extract_block(lines, start_idx, tag):
    """
    Extract a complete <tag>...</tag> block (tag is case-insensitive).
    Returns (block_lines, end_index) where end_index is the index of </tag>.
    """
    block = []
    depth = 0
    i     = start_idx
    tag_l = tag.lower()
    while i < len(lines):
        s = lines[i].strip().lower()
        if s == f'<{tag_l}>' or re.match(rf'^<{re.escape(tag_l)}[\s>]', s):
            depth += 1
        if depth > 0:
            block.append(lines[i])
        if s == f'</{tag_l}>':
            depth -= 1
            if depth == 0:
                return block, i
        i += 1
    return block, i


def _flatten_then_content(block_lines):
    """
    Recursively flatten the content of a <then> block:
    - Keep <item> blocks as-is
    - For nested <if> blocks: recurse into their <then> path only
    - Drop <report> blocks and <else> blocks
    """
    result = []
    i      = 0
    while i < len(block_lines):
        s = block_lines[i].strip().lower()

        if s == '<if>':
            nested_if, end_idx = _extract_block(block_lines, i, 'if')
            # Find and recurse into the nested <then>
            nested_then = []
            j = 0
            while j < len(nested_if):
                if nested_if[j].strip().lower() == '<then>':
                    then_blk, then_end = _extract_block(nested_if, j, 'then')
                    nested_then = then_blk[1:-1]    # strip <then> / </then> wrappers
                    break
                j += 1
            result.extend(_flatten_then_content(nested_then))
            i = end_idx + 1
            continue

        if re.match(r'<report\b', s):
            _, end_idx = _extract_block(block_lines, i, 'report')
            i = end_idx + 1
            continue

        result.append(block_lines[i])
        i += 1
    return result


def run_flatten(filepath):
    """
    Flatten nested <if> blocks in the normalized file in-place.
    Keeps the outer OS-detection if/condition/then/else intact.
    The outer <else> is reduced to a single FAILED report.
    """
    with open(filepath, encoding='utf-8') as f:
        lines = [ln.rstrip() for ln in f.readlines()]

    # Locate outermost <if>...</if>
    top_start = top_end = None
    depth = 0
    for idx, line in enumerate(lines):
        s = line.strip().lower()
        if top_start is None and s == '<if>':
            top_start = idx
            depth = 1
            continue
        if top_start is not None:
            if s == '<if>':
                depth += 1
            elif s == '</if>':
                depth -= 1
                if depth == 0:
                    top_end = idx
                    break

    if top_start is None or top_end is None:
        # No outer if found – write file unchanged
        print("  WARNING: Could not locate outer <if> block for flattening.")
        return

    header_lines = lines[:top_start]
    footer_lines = lines[top_end + 1:]
    body         = lines[top_start + 1 : top_end]

    condition_lines    = []
    outer_then_content = []
    outer_else_content = []

    i = 0
    while i < len(body):
        s = body[i].strip().lower()

        if re.match(r'<condition\b', body[i].strip(), re.IGNORECASE):
            cond_blk, end_idx = _extract_block(body, i, 'condition')
            condition_lines   = cond_blk
            i = end_idx + 1
            continue

        if s == '<then>':
            then_blk, end_idx = _extract_block(body, i, 'then')
            then_inner = then_blk[1:-1]

            # Preserve any leading <report> block (PASSED platform banner)
            leading_reports = []
            j = 0
            if then_inner and re.match(r'<report\b', then_inner[0].strip().lower()):
                rpt_blk, rpt_end = _extract_block(then_inner, 0, 'report')
                leading_reports = rpt_blk
                j = rpt_end + 1

            outer_then_content = leading_reports + _flatten_then_content(then_inner[j:])
            i = end_idx + 1
            continue

        if s == '<else>':
            else_blk, end_idx = _extract_block(body, i, 'else')
            else_inner = else_blk[1:-1]
            # Keep only the last <report> (FAILED banner)
            last_report = []
            k = 0
            while k < len(else_inner):
                if re.match(r'<report\b', else_inner[k].strip().lower()):
                    rpt, rpt_end = _extract_block(else_inner, k, 'report')
                    last_report  = rpt
                    k = rpt_end + 1
                    continue
                k += 1
            outer_else_content = last_report
            i = end_idx + 1
            continue

        i += 1

    # If no explicit else was found, create a minimal FAILED report
    if not outer_else_content:
        outer_else_content = [
            '    <report type:"FAILED">',
            '      description : "FAILED - TARGET OS DOES NOT MATCH BASELINE - IOS"',
            '      see_also    : "HTH"',
            '    </report>',
        ]

    out = []
    out.extend(header_lines)
    out.append('<if>')
    out.extend(condition_lines)
    out.append('  <then>')
    for ln in outer_then_content:
        out.append(ln)
    out.append('  </then>')
    out.append('')
    out.append('  <else>')
    for ln in outer_else_content:
        out.append(ln)
    out.append('  </else>')
    out.append('')
    out.append('</if>')
    out.extend(footer_lines)

    out = align_colons(out)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')

    item_count = sum(1 for ln in out if ln.strip() == '<item>')
    print(f"  After flatten    : {item_count} check items")


# =============================================================================
# COMBINE + DEDUP
# =============================================================================

def _normalise_fp_pattern(raw):
    return raw.strip().strip('"').strip("'").lower().strip()


def _get_fingerprint(fields):
    item_type = fields.get('type', '').strip().upper()
    item_val  = fields.get('item', '')
    context   = fields.get('context', '')
    regex_val = fields.get('regex', '')
    content   = fields.get('content', '')
    if item_type == 'BANNER_CHECK':
        pat  = _normalise_fp_pattern(item_val or '')
        cont = _normalise_fp_pattern(content)
        return f"banner|{pat}|{cont}" if (pat or cont) else None
    if item_type.startswith('CONFIG_CHECK'):
        pat = _normalise_fp_pattern(item_val) if item_val else _normalise_fp_pattern(regex_val)
        if not pat:
            return None
        ctx = _normalise_fp_pattern(context)
        return f"config|{ctx}|{pat}" if ctx else f"config|{pat}"
    return None


def _parse_combined_item_fields(block_text):
    fields = {}
    for field in ('type', 'description', 'info', 'reference', 'see_also',
                  'context', 'item', 'regex', 'content', 'is_substring'):
        m = re.search(rf'^\s*{re.escape(field)}\s*:\s*(.*)', block_text, re.MULTILINE)
        if m:
            fields[field] = m.group(1).strip()
    return fields


def _parse_normalized_items(filepath):
    """Extract all active <item> blocks from a normalized IOS audit file."""
    items = []
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = [ln.rstrip() for ln in f.readlines()]
    context_stack = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        slow = stripped.lower()
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
                fields = _parse_combined_item_fields(block_text)
                t = fields.get('type', '').upper()
                if t.startswith('CONFIG_CHECK') or t == 'BANNER_CHECK':
                    fields['_raw_lines'] = block
                    items.append(fields)
            continue
        i += 1
    return items


def _extract_wrapper(filepath):
    """Return (header_lines, footer_lines) split at first <then>...</then>."""
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = [ln.rstrip() for ln in f.readlines()]
    then_open = then_close = None
    for idx, line in enumerate(lines):
        s = line.strip().lower()
        if s == '<then>' and then_open is None:
            then_open = idx
        if s == '</then>':
            then_close = idx
    if then_open is None or then_close is None:
        return lines, []
    return lines[:then_open + 1], lines[then_close:]


def _renumber_combined(items):
    _desc_re = re.compile(
        r'^(\s*description\s*:\s*")(?:\d+\.\d+\s*-\s*NETIOS\s*-\s*)?(.*)',
        re.IGNORECASE
    )
    for counter, item in enumerate(items, 1):
        new_lines = []
        for line in item['_raw_lines']:
            m = _desc_re.match(line)
            if m:
                line = f'{m.group(1)}1.{counter:04d} - NETIOS - {m.group(2).rstrip(chr(34))}"'
            new_lines.append(line)
        item['_raw_lines'] = new_lines
    return items


def run_combine(normalized_files):
    """
    Deduplicate and merge all normalized files into IOS_Combined.audit.
    If IOS_Combined.audit already exists it is prepended to the file list so
    every previously-seen entry is preserved and only genuinely new checks
    from the freshly-processed files are appended.
    First file's wrapper is used. First occurrence of each fingerprint wins.
    """
    combined_path = os.path.join(OUTPUT_DIR, 'IOS_Combined.audit')
    if os.path.isfile(combined_path):
        # Avoid listing the combined file twice if the user somehow passed it in
        if combined_path not in normalized_files and \
                os.path.abspath(combined_path) not in [os.path.abspath(p) for p in normalized_files]:
            normalized_files = [combined_path] + list(normalized_files)
            print(f"  Including existing IOS_Combined.audit as base.")

    seen_fps  = {}
    all_items = []
    stats     = []

    for filepath in normalized_files:
        items        = _parse_normalized_items(filepath)
        added        = 0
        skipped_list = []
        for item in items:
            fp = _get_fingerprint(item)
            if fp is None or fp not in seen_fps:
                if fp:
                    seen_fps[fp] = os.path.basename(filepath)
                all_items.append(item)
                added += 1
            else:
                skipped_list.append(
                    (item.get('description', '').strip().strip('"'), seen_fps[fp]))
        stats.append({'file': os.path.basename(filepath),
                      'total': len(items), 'added': added,
                      'skipped': len(skipped_list), 'skipped_list': skipped_list})

    all_items = _renumber_combined(all_items)

    header_lines, footer_lines = _extract_wrapper(normalized_files[0])
    item_blocks = '\n\n'.join('\n'.join(item['_raw_lines']) for item in all_items)
    out_lines   = header_lines + [item_blocks, ''] + footer_lines
    flat        = '\n'.join(out_lines)
    content     = '\n'.join(align_colons(flat.splitlines())) + '\n'

    out_file = os.path.join(OUTPUT_DIR, 'IOS_Combined.audit')
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(content)

    # Print summary
    total_raw     = sum(s['total']   for s in stats)
    total_skipped = sum(s['skipped'] for s in stats)
    print(f"\n{'=' * 60}")
    print(f"COMBINE SUMMARY  ({'update — base + new files' if stats and stats[0]['file'] == 'IOS_Combined.audit' else 'fresh combine'})")
    print(f"{'=' * 60}")
    for s in stats:
        print(f"  {s['file'][:52]:<52}  {s['total']:>3} items  "
              f"{s['added']:>3} added  {s['skipped']:>3} duped")
    print(f"  {'-'*60}")
    print(f"  {'COMBINED TOTAL':<52}  {total_raw:>3} items  "
          f"{len(all_items):>3} kept   {total_skipped:>3} duped")
    print(f"{'=' * 60}")

    validate_audit_output(out_file)
    print(f"  Combined file : {out_file}")
    return out_file


# =============================================================================
# VALIDATION
# =============================================================================

def validate_audit_output(filepath):
    """Validate structural correctness of the output IOS audit file."""
    print(f"\n--- Validating: {os.path.basename(filepath)} ---")
    with open(filepath, encoding='utf-8') as f:
        lines = f.readlines()

    ct_open  = sum(1 for l in lines if '<check_type:' in l)
    ct_close = sum(1 for l in lines if l.strip() == '</check_type>')
    if_open  = sum(1 for l in lines if l.strip() == '<if>')
    if_close = sum(1 for l in lines if l.strip() == '</if>')

    structural_issues = []
    if ct_open != 1 or ct_close != 1:
        structural_issues.append(
            f"check_type tags: {ct_open} open / {ct_close} close (expected 1 each)")
    if if_open != if_close:
        structural_issues.append(
            f"Unmatched <if> tags: {if_open} open / {if_close} close")

    # Validate individual <item> blocks
    item_issues = []
    in_item     = False
    item_buf    = []
    item_count  = 0

    for line in lines:
        s = line.strip()
        if not in_item:
            if s == '<item>':
                in_item  = True
                item_buf = [s]
        else:
            item_buf.append(s)
            if s == '</item>':
                item_count += 1
                block = '\n'.join(item_buf)
                missing = []
                if not re.search(r'^\s*type\s*:', block, re.M):
                    missing.append('type')
                if not re.search(r'^\s*description\s*:', block, re.M):
                    missing.append('description')
                has_item    = bool(re.search(r'^\s*item\s*:', block, re.M))
                has_content = bool(re.search(r'^\s*content\s*:', block, re.M))
                if not has_item and not has_content:
                    missing.append('item/content')
                if missing:
                    dm   = re.search(r'description\s*:\s*"([^"]*)"', block)
                    desc = dm.group(1)[:70] if dm else '(unknown)'
                    item_issues.append((item_count, desc, missing))
                in_item  = False
                item_buf = []

    ok = not structural_issues and not item_issues
    if structural_issues:
        print("  STRUCTURAL ISSUES:")
        for iss in structural_issues:
            print(f"    {iss}")
    if item_issues:
        print(f"  ITEM FIELD ISSUES ({len(item_issues)}):")
        for n, desc, miss in item_issues[:10]:
            print(f"    block {n}: {desc}")
            print(f"      missing: {miss}")
    if ok:
        print(f"  All {item_count} <item> blocks: OK")
    print(f"  Result: {'PASS' if ok else 'FAIL — see errors above'}")
    return ok


# =============================================================================
# MAIN
# =============================================================================

def process_one_file(infile):
    """Run the full normalize→flatten pipeline on a single audit file.
    Returns the path to the normalized output, or None on failure.
    """
    if not os.path.isfile(infile):
        print(f"  ERROR: File not found — skipped: {infile}")
        return None

    print(f"\nProcessing: {os.path.basename(infile)}")
    print("-" * 60)

    print("  Step 1: Normalizing fields, variables, and item numbering ...")
    normalized, num_items = run_normalize(infile, BASELINE_VARS)

    print("  Step 2: Flattening nested if/then/else blocks ...")
    run_flatten(normalized)

    validate_audit_output(normalized)
    print(f"  DONE → {normalized}  ({num_items} items)")
    return normalized


def main():
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"Cisco IOS Audit Processor  [{ts}]")
    print("=" * 60)

    if IOS_AUDIT_FILES:
        files = IOS_AUDIT_FILES
        print(f"\nBatch mode: {len(files)} file(s) configured in IOS_AUDIT_FILES")
    else:
        # Interactive: accept one or more paths, one per line.
        # Empty line signals end of input.
        print("\nEnter audit file path(s). Press Enter on a blank line when done.")
        files = []
        while True:
            raw = input(f"  File {len(files)+1}: ").strip().strip('"').strip("'")
            if not raw:
                break
            files.append(os.path.abspath(raw))
        if not files:
            print("No files specified. Exiting.")
            return

    normalized_outputs = []
    for infile in files:
        result = process_one_file(os.path.abspath(infile))
        if result:
            normalized_outputs.append(result)

    print(f"\n{'=' * 60}")
    print(f"All {len(files)} file(s) processed.")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"{'=' * 60}")

    # Step 3 — combine all normalized outputs into one deduplicated file
    if len(normalized_outputs) > 1:
        print(f"\nStep 3: Combining {len(normalized_outputs)} normalized file(s) into IOS_Combined.audit ...")
        run_combine(normalized_outputs)
    elif len(normalized_outputs) == 1:
        print(f"\n(Only 1 file processed — no combine step needed.)")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
