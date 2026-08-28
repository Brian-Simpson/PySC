#!/usr/bin/env python3

import re
from pathlib import Path
import subprocess
import sys

# ==============================================================================
# CONFIGURATION
# ==============================================================================

if len(sys.argv) < 2:
    print("[-] Missing audit directory argument")
    sys.exit(1)

BASE_DIR = Path(sys.argv[1])

print(f"[+] Audit Directory : {BASE_DIR}")
print(f"[+] Controls File   : {BASE_DIR / 'controls.txt'}")
print(f"[+] Output File     : {BASE_DIR / 'normalized_custom_items.audit'}")

CONTROL_FILE = BASE_DIR / "controls.txt"
OUTPUT_FILE = BASE_DIR / "normalized_custom_items.audit"

# ==============================================================================
# LOAD CONTROL LIST
# ==============================================================================

controls = set()

with open(CONTROL_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        for item in line.split("|"):
            item = item.strip()

            if item:
                controls.add(item)

print(f"[+] Loaded {len(controls)} controls")

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def extract_fields(item_text):
    """
    Extract fields from a custom_item block while preserving
    multi-line values.
    """

    fields = {}

    pattern = re.compile(
        r'^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)(?=^\s*[A-Za-z0-9_]+\s*:|\Z)',
        re.MULTILINE | re.DOTALL
    )

    for match in pattern.finditer(item_text):
        field = match.group(1).strip()
        value = match.group(2).strip()

        # Ignore Windows Event IDs and other numeric keys
        if field.isdigit():
            continue

        fields[field] = value


    return fields


def extract_control_number(description):
    """
    Extract CIS control number from description.

    Example:
    17.1.1 Ensure ...
    18.10.57.3.11.1 Ensure ...
    """

    match = re.match(
        r'^"?([0-9]+(?:\.[0-9]+)+)',
        description
    )

    return match.group(1) if match else None


def normalize_info(info_value):
    """
    Keep only the first meaningful sentence and remove:
      - The recommended state
      - Note:
      - Notes:
      - Example:
      - Examples:
      - Impact:
      - Impacts:
      - Caution:
      - Cautions:
      - Important:
      - Warning:
      - Warnings:
      - Rationale:
      - Default Value:
      - Remediation:
    """

    info = info_value.strip()

    if info.startswith('"'):
        info = info[1:]

    if info.endswith('"'):
        info = info[:-1]

    # Remove html
    info = re.sub(r'<[^>]+>', '', info)

    # Normalize line endings
    info = info.replace("\r", "")

    stop_patterns = [
        r'The recommended state',
        r'Note\s*:',
        r'Notes\s*:',
        r'Impact\s*:',
        r'Impacts\s*:',
        r'Example\s*:',
        r'Examples\s*:',
        r'Caution\s*:',
        r'Cautions\s*:',
        r'Important\s*:',
        r'Warning\s*:',
        r'Warnings\s*:',
        r'Rationale\s*:',
        r'Default Value\s*:',
        r'Remediation\s*:'
    ]

    cutoff = len(info)

    for pattern in stop_patterns:
        match = re.search(
            pattern,
            info,
            re.IGNORECASE
        )

        if match:
            cutoff = min(cutoff, match.start())

    info = info[:cutoff].strip()

    # Collapse whitespace
    info = re.sub(r'\s+', ' ', info)

    # Keep first sentence only
    sentence_match = re.search(
        r'^(.*?[.!?])(?:\s|$)',
        info
    )

    if sentence_match:
        info = sentence_match.group(1).strip()
    else:
        info = info.strip()

    return f'"{info}"'


def normalize_reference(reference_value):
    """
    Extract only NIST 800-53 / 800-53r5 references.

    Output:
    NIST 800-53r5|AU-3 AU-12 IA-5
    """

    refs = []

    refs.extend(
        re.findall(
            r'800-53r5\|([A-Z]{2,4}-[A-Z0-9()\-]+)',
            reference_value,
            re.IGNORECASE
        )
    )

    refs.extend(
        re.findall(
            r'800-53\|([A-Z]{2,4}-[A-Z0-9()\-]+)',
            reference_value,
            re.IGNORECASE
        )
    )

    refs = list(dict.fromkeys(refs))

    if refs:
        return f'"NIST 800-53r5|{" ".join(refs)}"'

    return '"NIST 800-53r5|Not Mapped"'

def extract_nist_controls(reference_text):
    """
    Extract individual NIST 800-53 controls from a reference string.
    """

    controls = set()

    matches = re.findall(
        r'([A-Z]{2,4}-[A-Z0-9()\-]+)',
        reference_text,
        re.IGNORECASE
    )

    for match in matches:
        controls.add(match.upper())

    return controls

def format_field(name, value):
    return f"      {name:<24} : {value}"


# ==============================================================================
# FIND SOURCE AUDIT FILES
# ==============================================================================

audit_files = [
    f for f in BASE_DIR.glob("*.audit")
    if f.name not in {
        "matched_custom_items.audit",
        "normalized_custom_items.audit"
    }
]

print(f"[+] Found {len(audit_files)} audit files")


# ==============================================================================
# LOAD EXISTING BASELINE NIST COVERAGE
# ==============================================================================

baseline_nist_refs = set()

# Maps:
# SC-7(5) -> 1.0008
# AC-6    -> 1.0023
baseline_nist_map = {}

baseline_file = BASE_DIR / "MSWRK_Baseline.audit"

if baseline_file.exists():

    baseline_text = baseline_file.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    # Remove commented-out custom_item blocks
    baseline_text = re.sub(
        r"(?ms)^\s*#\s*<custom_item>.*?^\s*#\s*</custom_item>\s*$",
        "",
        baseline_text
    )

    baseline_items = re.findall(
        r'<custom_item>(.*?)</custom_item>',
        baseline_text,
        re.DOTALL | re.IGNORECASE
    )

    # print(f"[DEBUG] Baseline Items Loaded: {len(baseline_items)}")

    for item in baseline_items:

        fields = extract_fields(item)

        description = fields.get("description", "")
        reference = fields.get("reference", "")

        baseline_control_id = extract_control_number(
            description
        )

        item_refs = extract_nist_controls(
            reference
        )

        # print(f"[DEBUG] Description: {description}")
        # print(f"[DEBUG] Reference: {reference}")
        # print(f"[DEBUG] Extracted Refs: {item_refs}")

        for ref in item_refs:

            baseline_nist_refs.add(ref)

            if ref not in baseline_nist_map:
                baseline_nist_map[ref] = baseline_control_id

    print(
        f"[+] Loaded {len(baseline_nist_refs)} baseline NIST references"
    )

# ==============================================================================
# PROCESS AUDIT FILES
# ==============================================================================

seen_controls = set()

normalized_items = []

for audit_file in audit_files:

    print(f"[+] Processing {audit_file.name}")

    text = audit_file.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    custom_items = re.findall(
        r'<custom_item>(.*?)</custom_item>',
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    for item in custom_items:

        fields = extract_fields(item)

        if "description" not in fields:
            continue

        control_number = extract_control_number(
            fields["description"]
        )

        if not control_number:
            continue

        if control_number not in controls:
            continue

        if control_number in seen_controls:
            continue

        seen_controls.add(control_number)


        # ------------------------------------------------------------------
        # Normalize fields
        # ------------------------------------------------------------------

        if "info" in fields:
            fields["info"] = normalize_info(
                fields["info"]
            )

        if "reference" in fields:
            fields["reference"] = normalize_reference(
                fields["reference"]
            )
        else:
            fields["reference"] = '"NIST 800-53r5|Not Mapped"'

        # ----------------------------------------------------------
        # Skip controls whose NIST mappings already exist
        # in MSWRK_Baseline.audit
        # ----------------------------------------------------------

        item_nist_refs = extract_nist_controls(
            fields["reference"]
        )

        if item_nist_refs:

            if item_nist_refs.issubset(
                baseline_nist_refs
            ):

                for nist_ref in sorted(item_nist_refs):

                    baseline_control = baseline_nist_map.get(
                        nist_ref,
                        "UNKNOWN"
                    )

                    print(
                        f"[SKIP] {nist_ref} "
                        f"{control_number} "
                        f"covered by baseline control "
                        f"{baseline_control}"
                    )

                continue

        fields["see_also"] = '"See HTH Policies and Standards"'

        # Remove unwanted fields
        fields.pop("solution", None)
        fields.pop("Impact", None)
        fields.pop("Important", None)
        fields.pop("Note", None)
        fields.pop("Notes", None)
        fields.pop("Warning", None)
        fields.pop("Warnings", None)
        fields.pop("Caution", None)
        fields.pop("Example", None)

        # ------------------------------------------------------------------
        # Output field ordering
        # ------------------------------------------------------------------

        output_order = [
            "type",
            "description",
            "info",
            "reference",
            "see_also",
            "value_type",
            "value_data",
            "audit_policy_subcategory",
            "reg_option",
            "reg_item",
            "reg_key",
            "reg_value",
            "value_data_type",
            "service_name",
            "service_option",
            "file",
            "file_option",
            "check_type",
            "check_account",
            "password_policy",
            "policy_value",
            "option_type",
            "expected_value",
        ]

        block = ["<custom_item>"]

        for field in output_order:
            if field in fields:
                block.append(
                    format_field(
                        field,
                        fields[field]
                    )
                )

        # Add any remaining fields
        for field, value in fields.items():

            # Skip numeric fields such as
            # 4944, 4945, 4946, etc.
            if field.isdigit():
                continue

            if field not in output_order:
                block.append(
                    format_field(
                        field,
                        value
                    )
                )

        block.append("</custom_item>")

        # print(
        #     f"[DEBUG] Match: "
        #     f"{control_number} "
        #     f"from {audit_file.name}"
        # )

        normalized_items.append(
            "\n".join(block)
        )

# ==============================================================================
# WRITE OUTPUT
# ==============================================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as out:

    out.write(
        "\n\n".join(normalized_items)
    )

print()
print("=" * 80)
print(" GAP ANALYSIS RESULTS")
print("=" * 80)
print(f"Gaps Identified  : {len(normalized_items)}")
print(f"Output File      : {OUTPUT_FILE}")
print("=" * 80)
