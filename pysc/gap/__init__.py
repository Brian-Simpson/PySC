"""pysc.gap — NIST 800-53 gap analysis for HTH audit baselines.

- engine/extract/xlsx: platform gap analysis (baseline vs candidates against
  the OSCAL catalog, with recoverable coverage from commented-out checks)
- harvest: pull gap-closing checks out of candidate audits
- The whole-estate production reference gap analysis still runs via the
  legacy delegate (`pysc gap production`) until its extraction phase.
"""

from pysc.gap.engine import GapError, PlatformGapAnalysis, analyze_folder  # noqa: F401
from pysc.gap.harvest import harvest  # noqa: F401
