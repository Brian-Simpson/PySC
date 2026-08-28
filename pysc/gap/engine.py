"""Unified NIST 800-53 gap analysis engine.

Set semantics ported from the legacy interactive engine's main() derivations,
with its defects fixed by construction:
- the baseline audit is declared explicitly (pysc.toml platform profile or
  --baseline), with filename-contains-'baseline' only as a fallback — no more
  NameError when no baseline file exists;
- all files are parsed first, then the gap sets are derived once (the legacy
  loop recomputed and re-exported per file);
- no interactive prompts.
"""

import re
from collections import defaultdict
from pathlib import Path

from pysc.gap.extract import extract_active_checks, extract_inactive_checks
from pysc.nist.oscal import OscalCatalog, normalize_control_id


class GapError(RuntimeError):
    pass


class FileAnalysis:
    """One audit file's contribution to control coverage."""

    def __init__(self, path, checks, inactive_checks, covered, is_baseline):
        self.path = Path(path)
        self.short_name = self.path.name
        self.checks = checks                    # active checks (dicts)
        self.inactive_checks = inactive_checks  # commented-out checks (dicts)
        self.covered = covered                  # {control_id: [rule_ids]} incl. parent rollup
        self.is_baseline = is_baseline

    @property
    def checks_parsed(self):
        return len(self.checks)

    @property
    def covered_set(self):
        return set(self.covered.keys())


def _covered_map(checks, catalog):
    """{normalized control id: [rule ids]}, enhancements rolled up to parents.

    Port of legacy analyze_single_file(): each reference maps under its own
    (normalized) id AND under its parent control.
    """
    covered = defaultdict(list)
    for item in checks:
        for ctrl in item["controls"]:
            normalized = normalize_control_id(ctrl)
            if item["control_number"] not in covered[normalized]:
                covered[normalized].append(item["control_number"])
            parent = catalog.parent_of(normalized)
            if parent and item["control_number"] not in covered[parent]:
                covered[parent].append(item["control_number"])
    return dict(covered)


class PlatformGapAnalysis:
    """Baseline vs candidate audits for one platform, against the catalog."""

    def __init__(self, catalog, baseline, candidates, profile="full"):
        self.catalog = catalog
        self.baseline = baseline          # FileAnalysis
        self.candidates = candidates      # [FileAnalysis]
        self.profile = profile
        self.target_baseline = catalog.base_controls(profile)  # {id: title}
        self._derive()

    @property
    def files(self):
        return [self.baseline] + self.candidates

    def _derive(self):
        baseline_set = set(self.target_baseline.keys())

        self.all_possible_controls = set()
        for fa in self.files:
            self.all_possible_controls.update(fa.covered_set)

        self.baseline_covered_set = self.baseline.covered_set
        self.baseline_coverage_count = len(baseline_set & self.baseline_covered_set)

        # Base-catalog controls some file covers but the baseline audit doesn't.
        self.coverage_opportunities = (
            baseline_set & self.all_possible_controls
        ) - self.baseline_covered_set

        # Controls referenced by the baseline's commented-out checks.
        inactive_nist_controls = set()
        for item in self.baseline.inactive_checks:
            for ctrl in item["controls"]:
                inactive_nist_controls.add(normalize_control_id(ctrl))
        self.inactive_nist_controls = inactive_nist_controls

        # Recoverable: opportunities closable by un-commenting existing checks.
        self.inactive_coverage_opportunities = (
            inactive_nist_controls & self.coverage_opportunities
        )

        # Requires importing checks from candidate (CIS/DISA) audits.
        self.additional_controls_not_present = (
            self.coverage_opportunities - self.inactive_coverage_opportunities
        )

        # Rows for the "Inactive Coverage Opportunities" sheet.
        self.inactive_opportunity_rows = []
        for item in self.baseline.inactive_checks:
            matching = sorted(
                {
                    normalize_control_id(c)
                    for c in item["controls"]
                    if normalize_control_id(c) in self.inactive_coverage_opportunities
                }
            )
            if matching:
                self.inactive_opportunity_rows.append(
                    {
                        "rule_id": item["control_number"],
                        "description": item.get("description", ""),
                        "controls": matching,
                    }
                )

        # Checks (all files) referencing each control, for Reference Coverage.
        self.reference_counts = defaultdict(int)
        for fa in self.files:
            for control_id in fa.covered_set:
                self.reference_counts[control_id] += len(fa.covered[control_id])

    def summary_rows(self):
        baseline_set = set(self.target_baseline.keys())
        total = len(baseline_set)
        highest = len(baseline_set & self.all_possible_controls)
        rows = []
        for fa in self.files:
            covered_count = len(baseline_set & fa.covered_set)
            rows.append(
                {
                    "File": fa.short_name,
                    "Role": "Baseline" if fa.is_baseline else "Candidate",
                    "Checks Parsed": fa.checks_parsed,
                    "Current Coverage": self.baseline_coverage_count,
                    "Current Coverage %": _pct(self.baseline_coverage_count, total),
                    "Individual Coverage": covered_count,
                    "Individual Coverage %": _pct(covered_count, total),
                    "Highest Potential": highest,
                    "Highest Potential %": _pct(highest, total),
                }
            )
        return rows


def _pct(part, whole):
    return round((part / whole) * 100, 2) if whole else 0


def _find_baseline_path(audit_files, baseline_name):
    if baseline_name:
        wanted = Path(baseline_name).name.lower()
        for path in audit_files:
            if path.name.lower() == wanted:
                return path
        raise GapError(
            f"Declared baseline '{baseline_name}' not found among: "
            f"{[p.name for p in audit_files]}"
        )
    fallback = [p for p in audit_files if "baseline" in p.name.lower()]
    if len(fallback) == 1:
        return fallback[0]
    if not fallback:
        raise GapError(
            "No baseline audit: none declared (pysc.toml [platforms.<CODE>] "
            "baseline, or --baseline) and no filename contains 'baseline'."
        )
    raise GapError(
        f"Ambiguous baseline (declare one explicitly): {[p.name for p in fallback]}"
    )


def analyze_folder(folder, catalog_path, baseline_name=None, profile="full"):
    """Gap analysis over every .audit in a folder (one platform's worth)."""
    folder = Path(folder)
    audit_files = sorted(p for p in folder.glob("*.audit") if p.is_file())
    if not audit_files:
        raise GapError(f"No .audit files in {folder}")

    baseline_path = _find_baseline_path(audit_files, baseline_name)
    catalog = OscalCatalog.load(catalog_path)

    baseline_fa = None
    candidates = []
    for path in audit_files:
        checks = extract_active_checks(str(path))
        if not checks:
            print(f"[-] Skipping {path.name}: no parsable checks")
            continue
        is_baseline = path == baseline_path
        inactive = extract_inactive_checks(str(path)) if is_baseline else []
        fa = FileAnalysis(
            path, checks, inactive, _covered_map(checks, catalog), is_baseline
        )
        if is_baseline:
            baseline_fa = fa
        else:
            candidates.append(fa)

    if baseline_fa is None:
        raise GapError(f"Baseline file {baseline_path.name} produced no checks")

    return PlatformGapAnalysis(catalog, baseline_fa, candidates, profile)
