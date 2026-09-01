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
    production_root = str(Path(production_root)).lower()
    values = {}
    for occ in entry["occurrences"]:
        if str(Path(occ["file"]).parent).lower().startswith(production_root):
            values[occ["expected"]] = values.get(occ["expected"], 0) + 1
    return values


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
