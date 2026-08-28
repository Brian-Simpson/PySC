"""Harvest gap-closing checks from candidate audits.

Port of the legacy `Gap Controls.py` with its hardcoded MSWRK baseline fixed:
the baseline used for suppression is passed in (from pysc.toml platform config
or --baseline), and everything is callable as a function.

Given a controls list (CIS rule IDs) and a folder of candidate audits, emit a
ready-to-paste `normalized_custom_items.audit` containing the matching
<custom_item> blocks, normalized to HTH conventions (first-sentence info,
NIST-800-53r5-only reference, HTH see_also, fixed field order). Checks whose
NIST references are already fully covered by the baseline are skipped.
"""

import re
from pathlib import Path

OUTPUT_NAME = "normalized_custom_items.audit"
EXCLUDED_FILES = {"matched_custom_items.audit", OUTPUT_NAME}

SEE_ALSO = '"See HTH Policies and Standards"'
DROPPED_FIELDS = (
    "solution", "Impact", "Important", "Note", "Notes",
    "Warning", "Warnings", "Caution", "Example",
)
OUTPUT_ORDER = [
    "type", "description", "info", "reference", "see_also",
    "value_type", "value_data", "audit_policy_subcategory",
    "reg_option", "reg_item", "reg_key", "reg_value", "value_data_type",
    "service_name", "service_option", "file", "file_option",
    "check_type", "check_account", "password_policy", "policy_value",
    "option_type", "expected_value",
]

_FIELD_RE = re.compile(
    r"^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)(?=^\s*[A-Za-z0-9_]+\s*:|\Z)",
    re.MULTILINE | re.DOTALL,
)
_CUSTOM_ITEM_RE = re.compile(r"<custom_item>(.*?)</custom_item>", re.DOTALL | re.IGNORECASE)
_STRIP_INACTIVE_RE = re.compile(r"(?ms)^\s*#\s*<custom_item>.*?^\s*#\s*</custom_item>\s*$")

_STOP_PATTERNS = [
    r"The recommended state", r"Note\s*:", r"Notes\s*:", r"Impact\s*:",
    r"Impacts\s*:", r"Example\s*:", r"Examples\s*:", r"Caution\s*:",
    r"Cautions\s*:", r"Important\s*:", r"Warning\s*:", r"Warnings\s*:",
    r"Rationale\s*:", r"Default Value\s*:", r"Remediation\s*:",
]


def extract_fields(item_text):
    fields = {}
    for match in _FIELD_RE.finditer(item_text):
        field = match.group(1).strip()
        if field.isdigit():  # Windows Event IDs and other numeric keys
            continue
        fields[field] = match.group(2).strip()
    return fields


def extract_control_number(description):
    match = re.match(r'^"?([0-9]+(?:\.[0-9]+)+)', description)
    return match.group(1) if match else None


def normalize_info(info_value):
    info = info_value.strip()
    if info.startswith('"'):
        info = info[1:]
    if info.endswith('"'):
        info = info[:-1]
    info = re.sub(r"<[^>]+>", "", info).replace("\r", "")

    cutoff = len(info)
    for pattern in _STOP_PATTERNS:
        match = re.search(pattern, info, re.IGNORECASE)
        if match:
            cutoff = min(cutoff, match.start())
    info = re.sub(r"\s+", " ", info[:cutoff].strip())

    sentence = re.search(r"^(.*?[.!?])(?:\s|$)", info)
    info = sentence.group(1).strip() if sentence else info.strip()
    return f'"{info}"'


def normalize_reference(reference_value):
    refs = []
    refs.extend(re.findall(r"800-53r5\|([A-Z]{2,4}-[A-Z0-9()\-]+)", reference_value, re.IGNORECASE))
    refs.extend(re.findall(r"800-53\|([A-Z]{2,4}-[A-Z0-9()\-]+)", reference_value, re.IGNORECASE))
    refs = list(dict.fromkeys(refs))
    if refs:
        return f'"NIST 800-53r5|{" ".join(refs)}"'
    return '"NIST 800-53r5|Not Mapped"'


def extract_nist_controls(reference_text):
    return {
        m.upper()
        for m in re.findall(r"([A-Z]{2,4}-[A-Z0-9()\-]+)", reference_text, re.IGNORECASE)
    }


def _format_field(name, value):
    return f"      {name:<24} : {value}"


def load_controls_list(controls_file):
    controls = set()
    with open(controls_file, "r", encoding="utf-8") as fh:
        for line in fh:
            for item in line.strip().split("|"):
                item = item.strip()
                if item:
                    controls.add(item)
    return controls


def load_baseline_refs(baseline_path):
    """NIST refs actively covered by the baseline, and ref -> first rule id."""
    refs = set()
    ref_map = {}
    if not baseline_path:
        return refs, ref_map
    text = Path(baseline_path).read_text(encoding="utf-8", errors="ignore")
    text = _STRIP_INACTIVE_RE.sub("", text)
    for item in _CUSTOM_ITEM_RE.findall(text):
        fields = extract_fields(item)
        rule_id = extract_control_number(fields.get("description", ""))
        for ref in extract_nist_controls(fields.get("reference", "")):
            refs.add(ref)
            ref_map.setdefault(ref, rule_id)
    return refs, ref_map


def harvest(folder, controls_file=None, baseline_path=None, output_file=None):
    """Run the harvest; returns (output_path, harvested_count, skipped_rows)."""
    folder = Path(folder)
    controls_file = Path(controls_file) if controls_file else folder / "controls.txt"
    output_file = Path(output_file) if output_file else folder / OUTPUT_NAME
    if not controls_file.is_file():
        raise FileNotFoundError(f"Controls list not found: {controls_file}")

    wanted = load_controls_list(controls_file)
    baseline_refs, baseline_map = load_baseline_refs(baseline_path)

    audit_files = [
        f for f in sorted(folder.glob("*.audit")) if f.name not in EXCLUDED_FILES
    ]

    seen = set()
    blocks = []
    skipped = []
    for audit_file in audit_files:
        text = audit_file.read_text(encoding="utf-8", errors="ignore")
        for item in _CUSTOM_ITEM_RE.findall(text):
            fields = extract_fields(item)
            if "description" not in fields:
                continue
            rule_id = extract_control_number(fields["description"])
            if not rule_id or rule_id not in wanted or rule_id in seen:
                continue
            seen.add(rule_id)

            if "info" in fields:
                fields["info"] = normalize_info(fields["info"])
            fields["reference"] = normalize_reference(fields.get("reference", ""))

            item_refs = extract_nist_controls(fields["reference"])
            if item_refs and item_refs.issubset(baseline_refs):
                for ref in sorted(item_refs):
                    skipped.append(
                        {
                            "rule_id": rule_id,
                            "nist_ref": ref,
                            "covered_by": baseline_map.get(ref, "UNKNOWN"),
                        }
                    )
                continue

            fields["see_also"] = SEE_ALSO
            for name in DROPPED_FIELDS:
                fields.pop(name, None)

            block = ["<custom_item>"]
            for name in OUTPUT_ORDER:
                if name in fields:
                    block.append(_format_field(name, fields[name]))
            for name, value in fields.items():
                if not name.isdigit() and name not in OUTPUT_ORDER:
                    block.append(_format_field(name, value))
            block.append("</custom_item>")
            blocks.append("\n".join(block))

    output_file.write_text("\n\n".join(blocks), encoding="utf-8")
    return output_file, len(blocks), skipped
