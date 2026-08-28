"""Extraction of checks and NIST references from Tenable .audit files.

Regex semantics ported verbatim from the legacy interactive engine
(NIST_audit_Gap_Analysis.py extract_audit_items / extract_inactive_audit_items
/ extract_control_number) — proven against the HTH baseline corpus. Active
checks are non-commented <custom_item|item|report> blocks; inactive checks are
`#`-commented <custom_item> blocks (the "recoverable coverage" source).
"""

import os
import re

# Commented-out <custom_item> blocks (each line prefixed with #).
_INACTIVE_BLOCK_RE = re.compile(r"(?ms)^\s*#\s*<custom_item>(.*?)^\s*#\s*</custom_item>\s*$")
_STRIP_INACTIVE_RE = re.compile(r"(?ms)^\s*#\s*<custom_item>.*?^\s*#\s*</custom_item>\s*$")

_BLOCK_RE = re.compile(
    r"<(?:custom_item|item|report)>([\s\S]*?)</(?:custom_item|item|report)>",
    re.MULTILINE,
)

_NIST_REF_RE = re.compile(
    r"(?:800-53r5|800-53|NIST[\s\-_]SP[\s\-_]800-53(?:r5| Rev\.? 5)?)\|?([A-Z]{2}-\d+(?:\(\d+\))?)",
    re.IGNORECASE,
)

_COMMENT_PREFIX_RE = re.compile(r"(?m)^\s*#\s?")


def extract_control_number(description):
    """Leading dotted identifier of a check description (CIS rule / HTH id)."""
    match = re.match(r"^([\d\.]+)", description.strip())
    if match:
        return match.group(1).rstrip(".")
    return description


def _read(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def extract_active_checks(file_path):
    """Active (non-commented) checks: [{control_number, description, controls}]."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Audit file not found: {file_path}")

    content = _STRIP_INACTIVE_RE.sub("", _read(file_path))

    items = []
    for match in _BLOCK_RE.finditer(content):
        block_text = match.group(1)

        desc_match = re.search(r'description\s*:\s*"([^"]*)"', block_text, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else "Unnamed Check"

        ref_match = re.search(r'reference\s*:\s*["\'](.*?)["\']', block_text)
        references = ref_match.group(1) if ref_match else ""

        nist_controls = set()
        for found in _NIST_REF_RE.finditer(references + " " + block_text):
            nist_controls.add(found.group(1).upper())

        items.append(
            {
                "control_number": extract_control_number(description),
                "description": description,
                "controls": list(nist_controls),
            }
        )
    return items


def extract_inactive_checks(file_path):
    """`#`-commented <custom_item> checks — recoverable by un-commenting."""
    content = _read(file_path)

    inactive = []
    for match in _INACTIVE_BLOCK_RE.finditer(content):
        block_text = _COMMENT_PREFIX_RE.sub("", match.group(1))

        desc_match = re.search(r'description\s*:\s*"(.*?)"', block_text)
        description = desc_match.group(1) if desc_match else ""

        refs = set()
        for ref_match in _NIST_REF_RE.finditer(block_text):
            refs.add(ref_match.group(1).upper())

        inactive.append(
            {
                "control_number": extract_control_number(description),
                "description": description,
                "controls": sorted(refs),
            }
        )
    return inactive
