"""Enterprise policy-variance register.

Where HTH policy deliberately differs from vendor benchmark defaults (e.g. a
60-day maximum password age where CIS allows up to 365), the approved
expectation is recorded in policy_variances.toml (tracked in git). The library
then classifies every expectation variance:

  APPROVED_POLICY        approved value declared; baselines comply with it
  CONFLICTS_WITH_POLICY  approved value declared; a baseline disagrees
  BASELINE_CONFLICT      HTH baselines themselves carry conflicting values
  NEEDS_POLICY_DECISION  baselines agree on one value that differs from vendor
                         defaults, but no approval is recorded yet
  VENDOR_ONLY            variance exists only among vendor files

`pysc library seed-policy` drafts register entries for every
NEEDS_POLICY_DECISION control using the baseline value, for human curation.
"""

import re
import time
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib

REGISTER_NAME = "policy_variances.toml"


def load_register(path):
    path = Path(path)
    if not path.is_file():
        return {}
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return data.get("controls", {})


def _baseline_expectations(entry, production_root):
    """Expectations from RAW production baseline files only.

    Files directly in production_inputs are authoritative HTH baselines;
    their Normalized/ derivatives re-encode expectations (e.g. regex forms)
    and must not count as independent baseline opinions.
    """
    production_root = str(Path(production_root).resolve()).lower()
    values = {}
    for occ in entry["occurrences"]:
        if str(Path(occ["file"]).resolve().parent).lower() == production_root:
            values[occ["expected"]] = values.get(occ["expected"], 0) + 1
    return values


def _vendor_expectations(entry, vendor_root):
    """Expectations from RAW vendor benchmark files (the CIS recommendations)."""
    vendor_root = str(Path(vendor_root).resolve()).lower()
    values = {}
    sources = {}
    for occ in entry["occurrences"]:
        if str(Path(occ["file"]).resolve().parent).lower() == vendor_root:
            values[occ["expected"]] = values.get(occ["expected"], 0) + 1
            sources.setdefault(occ["expected"], set()).add(Path(occ["file"]).name)
    return values, sources


def classify_variances(entries, register, production_root):
    """Rows for every control with >1 distinct expectation."""
    rows = []
    for key, entry in sorted(entries.items()):
        if len(entry["expectations"]) < 2:
            continue
        baseline_values = _baseline_expectations(entry, production_root)
        approved = register.get(key, {}).get("approved")
        rationale = register.get(key, {}).get("rationale", "")

        if approved is not None:
            complies = not baseline_values or set(baseline_values) <= {str(approved)}
            status = "APPROVED_POLICY" if complies else "CONFLICTS_WITH_POLICY"
        elif len(baseline_values) > 1:
            status = "BASELINE_CONFLICT"
        elif len(baseline_values) == 1:
            status = "NEEDS_POLICY_DECISION"
        else:
            status = "VENDOR_ONLY"

        rows.append(
            {
                "key": key,
                "status": status,
                "approved": "" if approved is None else str(approved),
                "rationale": rationale,
                "baseline_values": dict(sorted(baseline_values.items())),
                "all_values": dict(sorted(entry["expectations"].items())),
            }
        )
    return rows


def _toml_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


_SEED_RATIONALE = "Seeded from HTH baseline value - review"
_RATIFY_RATIONALE = "HTH baseline value ratified as enterprise policy"


def write_register(register, register_path):
    """Write the full register deterministically (sorted by control key)."""
    lines = [
        "# Enterprise policy variances - approved expectations for controls where",
        "# HTH policy deliberately differs from vendor benchmark defaults.",
        "# Curate rationale text; entries here are authoritative for reporting.",
    ]
    for key in sorted(register):
        entry = register[key]
        lines.append("")
        lines.append(f'[controls."{_toml_escape(key)}"]')
        lines.append(f'approved = "{_toml_escape(entry.get("approved", ""))}"')
        lines.append(f'rationale = "{_toml_escape(entry.get("rationale", ""))}"')
    Path(register_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return register_path


def ratify_baselines(entries, register, production_root, register_path):
    """Adopt the raw-baseline expected value as enterprise policy for every
    variance control. Hand-curated rationales are preserved; seed placeholders
    and missing entries are (re)written with the baseline value.

    Returns (ratified_keys, true_conflicts) — a true conflict means the raw
    production baselines themselves disagree and needs a human decision.
    """
    merged = dict(register)
    ratified = []
    conflicts = []
    for key, entry in sorted(entries.items()):
        if len(entry["expectations"]) < 2:
            continue
        baseline_values = _baseline_expectations(entry, production_root)
        if not baseline_values:
            continue
        if len(baseline_values) > 1:
            conflicts.append({"key": key, "baseline_values": baseline_values})
            continue
        baseline_value = next(iter(baseline_values))
        existing = merged.get(key, {})
        curated = existing.get("rationale", "") not in ("", _SEED_RATIONALE)
        if curated and str(existing.get("approved", "")) == baseline_value:
            continue  # already hand-ratified
        merged[key] = {
            "approved": baseline_value,
            "rationale": existing.get("rationale") if curated else _RATIFY_RATIONALE,
        }
        ratified.append(key)
    write_register(merged, register_path)
    return ratified, conflicts


def cis_variance_rows(entries, register, production_root, vendor_root):
    """The deviation register: controls where the HTH baseline/approved value
    differs from the CIS-recommended value(s) in the raw vendor benchmarks."""
    rows = []
    for key, entry in sorted(entries.items()):
        baseline_values = _baseline_expectations(entry, production_root)
        vendor_values, vendor_sources = _vendor_expectations(entry, vendor_root)
        if not vendor_values:
            continue
        approved = register.get(key, {}).get("approved")
        hth_value = (
            str(approved)
            if approved is not None and str(approved) != ""
            else (next(iter(baseline_values)) if len(baseline_values) == 1 else None)
        )
        if hth_value is None or hth_value in vendor_values:
            continue
        example = entry["occurrences"][0]
        cis_files = sorted({f for files in vendor_sources.values() for f in files})
        rows.append(
            {
                "key": key,
                "readable": entry.get("readable", ""),
                "platforms": " ".join(sorted(entry.get("platforms", []))),
                "hth_value": hth_value,
                "cis_values": " | ".join(sorted(vendor_values)),
                "cis_sources": "; ".join(cis_files),
                "nist_refs": " ".join(sorted(entry.get("nist_refs", []))),
                "rationale": register.get(key, {}).get("rationale", ""),
                "description": example["description"],
            }
        )
    return rows


def seed_register(entries, register, production_root, register_path):
    """Append NEEDS_POLICY_DECISION controls to the register (baseline value
    as the proposed approval). Existing entries are never modified."""
    rows = classify_variances(entries, register, production_root)
    candidates = [r for r in rows if r["status"] == "NEEDS_POLICY_DECISION"]
    conflicts = [r for r in rows if r["status"] == "BASELINE_CONFLICT"]

    register_path = Path(register_path)
    lines = []
    if not register_path.is_file():
        lines.append("# Enterprise policy variances - approved expectations for controls where")
        lines.append("# HTH policy deliberately differs from vendor benchmark defaults.")
        lines.append("# Curate rationale text; entries here are authoritative for reporting.")
        lines.append("")
    else:
        lines.append("")
        lines.append(f"# --- Seeded {time.strftime('%Y-%m-%d')} from HTH baseline values (review + edit rationale) ---")

    for row in candidates:
        baseline_value = next(iter(row["baseline_values"]))
        lines.append("")
        lines.append(f'[controls."{_toml_escape(row["key"])}"]')
        lines.append(f'approved = "{_toml_escape(baseline_value)}"')
        lines.append('rationale = "Seeded from HTH baseline value - review"')

    if candidates:
        with open(register_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return candidates, conflicts
