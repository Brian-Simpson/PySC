#!/usr/bin/env python3
"""Shared parser helpers for .audit normalization scripts.

This module intentionally provides a small, dependency-free surface:
- extract_variables(lines)
- parse_document(lines)
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Iterable, List, Dict, Any

_START_BLOCK_RE = re.compile(r"^\s*<\s*(custom_item|report)\b([^>]*)>\s*$", re.IGNORECASE)
_END_CUSTOM_RE = re.compile(r"^\s*</\s*custom_item\s*>\s*$", re.IGNORECASE)
_END_REPORT_RE = re.compile(r"^\s*</\s*report\s*>\s*$", re.IGNORECASE)
_FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
_REPORT_TYPE_RE = re.compile(r"\btype\s*:\s*\"?([A-Za-z-]+)\"?", re.IGNORECASE)

# Conservative variable capture used in these .audit files.
# Examples handled:
#   SOME_VAR = "value"
#   SOME_VAR: "value"
#   SOME_VAR = value
_VAR_LINE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.*?)\s*$"
)


def _ensure_lines(text_or_lines: Iterable[str] | str) -> List[str]:
    if isinstance(text_or_lines, str):
        return text_or_lines.splitlines()
    return [str(x).rstrip("\n") for x in text_or_lines]


def _strip_outer_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def extract_variables(text_or_lines: Iterable[str] | str) -> Dict[str, str]:
    """Extract top-level variable definitions.

    To avoid false positives on regular field lines inside blocks, this only scans
    lines before the first known block start.
    """
    lines = _ensure_lines(text_or_lines)
    variables: Dict[str, str] = {}

    for line in lines:
        if _START_BLOCK_RE.match(line):
            break

        m = _VAR_LINE_RE.match(line)
        if not m:
            continue

        key, value = m.group(1), m.group(2)

        # Ignore obvious non-variable structural lines.
        if key.lower() in {"type", "description", "info", "reference"}:
            continue
        if value.startswith("<") and value.endswith(">"):
            continue

        variables[key] = _strip_outer_quotes(value)

    # Also support commented XML-style variable blocks used in many .audit files:
    #   # <variable>
    #   #   <name>MINIMUM_PASSWORD_LENGTH</name>
    #   #   <default>[14..MAX]</default>
    #   # </variable>
    in_variable = False
    var_name = ""
    var_default = ""

    for line in lines:
        cleaned = re.sub(r"^\s*#\s*", "", line).strip()
        lowered = cleaned.lower()

        if lowered == "<variable>":
            in_variable = True
            var_name = ""
            var_default = ""
            continue

        if not in_variable:
            continue

        if lowered == "</variable>":
            if var_name and var_default:
                variables[var_name] = _strip_outer_quotes(var_default)
            in_variable = False
            var_name = ""
            var_default = ""
            continue

        m_name = re.match(r"^<name>(.*?)</name>$", cleaned, flags=re.IGNORECASE)
        if m_name:
            var_name = m_name.group(1).strip()
            continue

        m_default = re.match(r"^<default>(.*?)</default>$", cleaned, flags=re.IGNORECASE)
        if m_default:
            var_default = m_default.group(1).strip()

    return variables


def parse_document(text_or_lines: Iterable[str] | str) -> List[Dict[str, Any]]:
    """Parse an audit file into text and block nodes.

    Node shapes:
      {"type": "text", "text": "..."}
      {"type": "custom_item", "fields": OrderedDict(...)}
      {"type": "report-warning", "fields": OrderedDict(...)}
      {"type": "report-passed", "fields": OrderedDict(...)}
    """
    lines = _ensure_lines(text_or_lines)
    document: List[Dict[str, Any]] = []

    in_block = False
    block_type = ""
    block_fields: OrderedDict[str, str] = OrderedDict()
    last_key = ""

    for line in lines:
        if not in_block:
            m_start = _START_BLOCK_RE.match(line)
            if not m_start:
                document.append({"type": "text", "text": line})
                continue

            tag = m_start.group(1).lower()
            attrs = m_start.group(2) or ""
            if tag == "report":
                t = "warning"
                m_type = _REPORT_TYPE_RE.search(attrs)
                if m_type:
                    raw = m_type.group(1).strip().lower()
                    if raw == "passed":
                        t = "passed"
                    elif raw == "warning":
                        t = "warning"
                block_type = f"report-{t}"
            else:
                block_type = "custom_item"

            block_fields = OrderedDict()
            last_key = ""
            in_block = True
            continue

        # Inside a block
        if block_type.startswith("report") and _END_REPORT_RE.match(line):
            document.append({"type": block_type, "fields": block_fields})
            in_block = False
            block_type = ""
            block_fields = OrderedDict()
            last_key = ""
            continue

        if block_type == "custom_item" and _END_CUSTOM_RE.match(line):
            document.append({"type": block_type, "fields": block_fields})
            in_block = False
            block_type = ""
            block_fields = OrderedDict()
            last_key = ""
            continue

        m_field = _FIELD_RE.match(line)
        if m_field:
            key = m_field.group(1).strip()
            value = m_field.group(2).strip()
            block_fields[key] = value
            last_key = key
            continue

        # Preserve wrapped/multiline values by appending non-empty continuation
        # lines to the most recently parsed field.
        if last_key and line.strip():
            block_fields[last_key] = (block_fields[last_key] + " " + line.strip()).strip()

    # If the file ends with an unclosed block, emit what was parsed.
    if in_block and block_type:
        document.append({"type": block_type, "fields": block_fields})

    return document
