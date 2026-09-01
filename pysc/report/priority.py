"""Ranked remediation priorities across the enterprise gap results.

Shared by the Unified_Compliance_Matrix Priority_Gaps sheet and the executive
dashboard. Scoring follows the production gap-analysis convention: security-
critical NIST families (AC, IA, AU, SC, SI) weigh x3, and a fully missing
control (needs a new check imported) outranks a recoverable one (un-comment
an existing check) x2 vs x1.
"""

from pysc.nist.oscal import OscalCatalog

PRIORITY_FAMILIES = {"AC", "IA", "AU", "SC", "SI"}


def priority_gap_rows(result, limit=None):
    """[{score, platform, control_id, title, family, family_name, action}]
    sorted highest priority first."""
    rows = []
    for code, analysis in sorted(result.analyses.items()):
        for control_id in sorted(analysis.coverage_opportunities):
            family, family_name = OscalCatalog.family_of(control_id)
            recoverable = control_id in analysis.inactive_coverage_opportunities
            weight = 3 if family in PRIORITY_FAMILIES else 1
            score = weight * (1 if recoverable else 2)
            rows.append(
                {
                    "score": score,
                    "platform": code,
                    "control_id": control_id,
                    "title": analysis.catalog.title(control_id),
                    "family": family,
                    "family_name": family_name,
                    "recoverable": recoverable,
                    "action": (
                        "Un-comment existing check"
                        if recoverable
                        else "Import candidate check"
                    ),
                }
            )
    rows.sort(key=lambda r: (-r["score"], r["platform"], r["control_id"]))
    return rows[:limit] if limit else rows
