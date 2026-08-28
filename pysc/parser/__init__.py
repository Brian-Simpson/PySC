"""pysc.parser — Tenable .audit document parsing.

Re-exports the parsing layer from the normalization core (single source of
truth; extracted verbatim from the legacy engine).
"""

from pysc.normalize._core import (  # noqa: F401
    determine_platform_from_filename,
    extract_variables,
    parse_document,
)
from pysc.normalize._core import (  # noqa: F401
    _parse_document_for_platform as parse_document_for_platform,
    _sanitize_audit_lines as sanitize_audit_lines,
    _strip_bom_prefix as strip_bom_prefix,
)
