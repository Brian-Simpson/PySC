"""Filename -> platform classification.

The authoritative mapping is declarative: each [platforms.<CODE>] section in
pysc.toml lists the filename_tokens (case-insensitive substrings) that
identify that platform in Tenable .audit file names, e.g. "SQL_Server" -> SQL,
"Cisco_NX" -> NetNXOS. When several tokens match, the longest (most specific)
wins. Files matching no token fall back to the legacy filename heuristic
(pysc.parser.determine_platform_from_filename) via DETECTION_TO_PLATFORM.
"""

from pathlib import Path

from pysc.parser import determine_platform_from_filename

# Legacy determine_platform_from_filename() codes -> pysc.toml platform codes
DETECTION_TO_PLATFORM = {
    "VMware": "VMware",
    "MSSRV": "MSSRV",
    "MSWRK": "MSWRK",
    "RHEL": "RHEL",
    "SQL": "SQL",
    "IOS": "NetIOS",
    "PAFW": "NetPAFW",
    "NX-OS": "NetNXOS",
    "F5": "NetF5",
    "MSAZ": "Azure",
    "ASA": "NetASA",
    "Amazon": "AWS",
}


# Alternate spellings accepted for platform codes (user input, legacy data).
PLATFORM_ALIASES = {
    "MSSQL": "SQL",
}


def canonical_platform(code):
    """Canonical platform code for user/legacy input (MSSQL -> SQL)."""
    if not code:
        return code
    return PLATFORM_ALIASES.get(code.upper(), code)


class PlatformMatcher:
    def __init__(self, tokens_by_code, use_fallback=True):
        # [(token_lower, code)] sorted longest-token-first for specificity.
        self._tokens = sorted(
            (
                (token.lower(), code)
                for code, tokens in tokens_by_code.items()
                for token in tokens
            ),
            key=lambda pair: -len(pair[0]),
        )
        self._codes = set(tokens_by_code)
        self._use_fallback = use_fallback

    @classmethod
    def from_config(cls, cfg):
        tokens_by_code = {
            code: profile.get("filename_tokens", [])
            for code, profile in cfg.platforms().items()
        }
        matcher = cls(tokens_by_code)
        matcher._codes = set(cfg.platforms())
        return matcher

    def match(self, filename):
        """Platform code for a filename, or None if unclassifiable."""
        name = Path(filename).name.lower()
        for token, code in self._tokens:
            if token and token in name:
                return code
        if self._use_fallback:
            detected = determine_platform_from_filename(str(filename))
            code = DETECTION_TO_PLATFORM.get(detected)
            if code in self._codes:
                return code
        return None
