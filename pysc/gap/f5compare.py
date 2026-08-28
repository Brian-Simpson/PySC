"""F5 baseline vs CIS structural comparison.

Port of compare_f5_baseline_vs_cis.py (the superset of the two near-duplicate
legacy scripts): active blocks are matched between the baseline and comparison
audits by their (f5_command, json_transform) signature; comparison blocks with
no baseline match are "orphaned" and can be spliced into a copy of the
baseline for review. Baseline selection is explicit (config/--baseline) with
the legacy filename-contains-'baseline' fallback.
"""

import re
import time
from collections import Counter
from pathlib import Path

SIGNATURE_FIELDS = ("f5_command", "json_transform")

_BLOCK_RE = re.compile(
    r"(?ms)^(?!\s*#)\s*<(?:custom_item|item)>(.*?)^\s*</(?:custom_item|item)>[ \t]*$"
)
_FIELD_RE = re.compile(
    r"^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)(?=^\s*[A-Za-z0-9_]+\s*:|\Z)",
    re.MULTILINE | re.DOTALL,
)
_FILE_REF_RE = re.compile(r'^\s*reference\s*:\s*["\'](.*?)["\']', re.MULTILINE)


def _canonical(value):
    value = (value or "").strip()
    if value.startswith(('"', "'")) and value.endswith(('"', "'")) and len(value) >= 2:
        value = value[1:-1]
    return re.sub(r"\s+", " ", value).strip()


def parse_blocks(path):
    """Active blocks with both signature fields: [{fields, signature, raw}]."""
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    file_ref_match = _FILE_REF_RE.search(text)
    file_reference = file_ref_match.group(1) if file_ref_match else ""

    blocks = []
    for match in _BLOCK_RE.finditer(text):
        body = match.group(1)
        fields = {}
        for m in _FIELD_RE.finditer(body):
            fields[m.group(1).strip()] = m.group(2).strip()
        if not all(fields.get(f) for f in SIGNATURE_FIELDS):
            continue
        if not fields.get("reference") and file_reference:
            fields["reference"] = file_reference
        signature = tuple(_canonical(fields[f]) for f in SIGNATURE_FIELDS)
        blocks.append({"fields": fields, "signature": signature, "raw": match.group(0)})
    return blocks


def compare(baseline_path, comparison_paths):
    """Multiset signature match; returns per-file results and orphans."""
    baseline_blocks = parse_blocks(baseline_path)
    baseline_sigs = Counter(b["signature"] for b in baseline_blocks)

    results = []
    all_orphans = []
    for path in comparison_paths:
        blocks = parse_blocks(path)
        available = Counter(baseline_sigs)
        matching = 0
        orphans = []
        for block in blocks:
            if available[block["signature"]] > 0:
                available[block["signature"]] -= 1
                matching += 1
            else:
                orphans.append(block)
        results.append(
            {
                "file": Path(path).name,
                "active": len(blocks),
                "matching": matching,
                "orphaned": len(orphans),
                "orphan_blocks": orphans,
            }
        )
        all_orphans.extend(orphans)
    return {
        "baseline_file": Path(baseline_path).name,
        "baseline_active": len(baseline_blocks),
        "results": results,
        "orphans": all_orphans,
    }


def splice_orphans(baseline_path, orphans, output_path=None):
    """Clone the baseline with orphan blocks inserted before </check_type>."""
    baseline_path = Path(baseline_path)
    text = baseline_path.read_text(encoding="utf-8", errors="ignore")
    if output_path is None:
        stamp = time.strftime("%y%m%d%H%M")
        output_path = baseline_path.with_name(
            f"F5_Audit_with_orphaned_controls_{stamp}.audit"
        )
    insertion = "\n\n".join(b["raw"].strip("\n") for b in orphans)
    idx = text.rfind("</check_type>")
    if idx == -1:
        text = text.rstrip("\n") + "\n\n" + insertion + "\n"
    else:
        text = text[:idx] + insertion + "\n\n" + text[idx:]
    Path(output_path).write_text(text, encoding="utf-8")
    return Path(output_path)


def write_comparison_workbook(comparison, output_path):
    from openpyxl import Workbook

    from pysc.report.excel_util import write_sheet

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    rows = [
        [comparison["baseline_file"], "Baseline", comparison["baseline_active"], "", ""]
    ]
    for r in comparison["results"]:
        rows.append([r["file"], "Comparison", r["active"], r["matching"], r["orphaned"]])
    write_sheet(
        ws,
        ["Audit file", "Role", "Active controls", "Matching controls", "Orphaned controls"],
        rows,
    )

    ws2 = wb.create_sheet("Orphaned Controls")
    write_sheet(
        ws2,
        ["Description", "Reference", "f5_command", "json_transform"],
        [
            [
                _canonical(b["fields"].get("description", "")),
                _canonical(b["fields"].get("reference", "")),
                b["signature"][0],
                b["signature"][1],
            ]
            for b in comparison["orphans"]
        ],
    )
    wb.save(output_path)
    return output_path
