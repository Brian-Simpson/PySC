"""Enterprise-wide gap analysis over the canonical input trees.

For each platform declared in pysc.toml: baseline = the production audit in
actual_audit_inputs (per [platforms.<CODE>] baseline), candidates = the vendor
CIS/DISA audits in audit_inputs classified by the declared filename_tokens
(pysc.platforms.PlatformMatcher). Platforms without a declared baseline are
reported as such — that absence is itself a finding for the executive report.
"""

from pysc.gap.engine import analyze_files
from pysc.nist.oscal import OscalCatalog
from pysc.platforms import DETECTION_TO_PLATFORM, PlatformMatcher  # noqa: F401 (re-export)


class EnterpriseGapResult:
    def __init__(self, analyses, missing_baseline, unmatched_candidates):
        self.analyses = analyses                    # {platform_code: PlatformGapAnalysis}
        self.missing_baseline = missing_baseline    # {platform_code: [candidate names]}
        self.unmatched_candidates = unmatched_candidates  # [names with no platform]


def candidates_by_platform(cfg):
    """Vendor audits in audit_inputs grouped by pysc.toml platform code."""
    vendor_root = cfg.path("vendor_inputs")
    matcher = PlatformMatcher.from_config(cfg)
    grouped = {}
    unmatched = []
    for path in sorted(vendor_root.glob("*.audit")):
        code = matcher.match(path.name)
        if code:
            grouped.setdefault(code, []).append(path)
        else:
            unmatched.append(path.name)
    return grouped, unmatched


def analyze_enterprise(cfg, profile="full"):
    catalog = OscalCatalog.load(cfg.path("oscal_catalog"))
    grouped, unmatched = candidates_by_platform(cfg)

    analyses = {}
    missing_baseline = {}
    for code in sorted(cfg.platforms()):
        baseline_path = cfg.baseline_path(code)
        candidates = grouped.get(code, [])
        if baseline_path is None or not baseline_path.is_file():
            missing_baseline[code] = [p.name for p in candidates]
            continue
        analyses[code] = analyze_files(
            baseline_path, candidates, None, profile=profile, catalog=catalog
        )
    return EnterpriseGapResult(analyses, missing_baseline, unmatched)
