"""MITRE ATT&CK exposure derived from open NIST 800-53 gaps.

Uses the CTID ATT&CK <-> 800-53r5 'mitigates' mappings: every open gap
control weakens the mitigation of specific ATT&CK techniques. Aggregating
across platforms surfaces the common approach vectors an adversary would
find least resisted — the executive answer to "what do these gaps mean?".
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from pysc.nist.oscal import normalize_control_id


def load_attack_mappings(path):
    """{base control id: [(technique_id, technique_name), ...]}"""
    path = Path(path)
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    by_control = defaultdict(list)
    for obj in data.get("mapping_objects", []):
        control = obj.get("capability_id")
        if not control or obj.get("status") == "non_mappable":
            continue
        if obj.get("mapping_type") != "mitigates":
            continue
        control = normalize_control_id(control)
        by_control[control].append(
            (obj.get("attack_object_id", ""), obj.get("attack_object_name", ""))
        )
    return dict(by_control)


def _parent_technique(technique_id):
    return technique_id.split(".")[0]


def attack_vectors_for_gaps(result, mappings, limit=None):
    """Rank ATT&CK techniques whose mitigating controls are open gaps.

    Sub-techniques roll up under their parent technique so the list reads as
    approach vectors rather than a wall of variants. Ranked by breadth:
    platforms affected, then number of distinct weakened controls.
    """
    vectors = {}
    for code, analysis in sorted(result.analyses.items()):
        gaps = {normalize_control_id(c) for c in analysis.coverage_opportunities}
        for control_id in gaps:
            for technique_id, technique_name in mappings.get(control_id, []):
                parent = _parent_technique(technique_id)
                entry = vectors.setdefault(
                    parent,
                    {
                        "technique_id": parent,
                        "technique_name": technique_name if technique_id == parent else "",
                        "sub_techniques": set(),
                        "controls": set(),
                        "platforms": set(),
                    },
                )
                if technique_id == parent and technique_name:
                    entry["technique_name"] = technique_name
                elif not entry["technique_name"]:
                    entry["technique_name"] = re.sub(r"\.\d+$", "", technique_name)
                if technique_id != parent:
                    entry["sub_techniques"].add(technique_id)
                entry["controls"].add(control_id)
                entry["platforms"].add(code)

    rows = []
    for entry in vectors.values():
        rows.append(
            {
                "technique_id": entry["technique_id"],
                "technique_name": entry["technique_name"],
                "platforms": sorted(entry["platforms"]),
                "controls": sorted(entry["controls"]),
                "sub_technique_count": len(entry["sub_techniques"]),
            }
        )
    rows.sort(
        key=lambda r: (-len(r["platforms"]), -len(r["controls"]), r["technique_id"])
    )
    return rows[:limit] if limit else rows
