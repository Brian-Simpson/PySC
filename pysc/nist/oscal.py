"""NIST SP 800-53 rev5 OSCAL catalog access.

Ported from the legacy interactive engine (NIST_audit_Gap_Analysis.py
load_local_oscal_baseline / NIST_FAMILIES), made non-interactive and
path-configurable.
"""

import json
import re
from pathlib import Path

NIST_FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

BASELINE_PROFILES = ("full", "high", "moderate", "low")


class OscalError(RuntimeError):
    pass


def normalize_control_id(control_id):
    """Canonical control ID: uppercase, zero-padding stripped (AC-02 -> AC-2)."""
    return re.sub(r"-0(\d)", r"-\1", control_id.strip().upper())


class OscalCatalog:
    """The 800-53r5 control catalog: id -> title, enhancement -> parent."""

    def __init__(self, controls, parents):
        self.controls = controls  # {control_id: title}
        self.parents = parents    # {enhancement_id: parent_id}

    @classmethod
    def load(cls, path):
        path = Path(path)
        if not path.is_file():
            raise OscalError(
                f"NIST OSCAL catalog not found: {path} "
                "(set [paths].oscal_catalog in pysc.toml)"
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            raise OscalError(f"Cannot parse OSCAL catalog {path}: {exc}")

        controls = {}
        parents = {}

        def recurse(control_list, parent_id=None):
            for ctrl in control_list:
                ctrl_id = ctrl.get("id", "").upper()
                title = ctrl.get("title", "No Title Available")
                if ctrl_id:
                    controls[ctrl_id] = title
                    if parent_id:
                        parents[ctrl_id] = parent_id
                if "controls" in ctrl:
                    recurse(ctrl["controls"], parent_id=ctrl_id if not parent_id else parent_id)

        for group in data.get("catalog", {}).get("groups", []):
            if "controls" in group:
                recurse(group["controls"])

        if not controls:
            raise OscalError(f"OSCAL catalog {path} contains no controls")
        return cls(controls, parents)

    def base_controls(self, profile="full"):
        """Base controls (no enhancements) for the chosen baseline profile.

        Only 'full' is available: the OSCAL LOW/MODERATE/HIGH baseline profile
        documents are separate downloads the workspace does not have. The
        legacy prompt silently ignored the choice; here it is an explicit error.
        """
        if profile != "full":
            raise OscalError(
                f"Baseline profile '{profile}' is not available: the OSCAL "
                "impact-baseline profiles are not present in this workspace. "
                "Use 'full' (complete catalog)."
            )
        return {k: v for k, v in self.controls.items() if "(" not in k}

    def title(self, control_id):
        return self.controls.get(control_id, "Unknown Control")

    def parent_of(self, control_id):
        """Parent for an enhancement; falls back to splitting on '('."""
        if control_id in self.parents:
            return self.parents[control_id]
        if "(" in control_id:
            return control_id.split("(")[0]
        return None

    @staticmethod
    def family_of(control_id):
        family_id = control_id.split("-")[0].upper()
        return family_id, NIST_FAMILIES.get(family_id, "Unknown Family")
