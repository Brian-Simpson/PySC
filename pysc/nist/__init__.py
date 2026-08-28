"""pysc.nist — NIST SP 800-53 reference handling.

references: normalization of audit `reference:` fields to 800-53r5 tokens
(re-exported from the normalization core). The OSCAL catalog loader and gap
engine land here in Phase 3.
"""

from pysc.normalize._core import normalize_reference  # noqa: F401
