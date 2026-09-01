"""Human-readable rendering of expected values.

Audit checks encode expectations in several syntaxes: plain literals, Tenable
ranges ([1..365]), audit-OR strings (A" || "B), and CHECK_REGEX patterns.
Reports should show the policy MEANING, not the implementation, so
decode_expected() translates the recognized forms:

  ^(1|2|...|30)$                          -> 1 to 30
  ^([1-9][0-9]{5,}|...|3276[8-9])$        -> 32768 or greater   (inferred by probing)
  ^(Success|Success\\ and\\ Failure)$     -> Success or Success and Failure
  Disabled" || "Not Found                 -> Disabled or Not Found
  (^A$)|(^A, B$)                          -> A or A, B
  ^(?=.*X)(?=.*Y)?.*$                     -> includes X (optional: Y)
  [1..365]                                -> 1 to 365

Anything unrecognized is returned unchanged.
"""

import re

_FLAG_PREFIX_RE = re.compile(r"^\(\?[simx]+\)")
_TENABLE_RANGE_RE = re.compile(r"^\[(\d+)\.\.(\d+)\]$")
_AUDIT_OR_SPLIT_RE = re.compile(r'"?\s*\|\|\s*"?')
_INT_RE = re.compile(r"^\d+$")
_LITERAL_ALT_RE = re.compile(r"^[A-Za-z0-9 ,._\-]+$")
_ANCHORED_GROUP_ALT_RE = re.compile(r"^\(\^(.*?)\$\)(\|\(\^(.*?)\$\))+$")
_LOOKAHEAD_RE = re.compile(r"\(\?=\.\*([^)]+)\)(\?)?")
_NUMERIC_PATTERN_CHARS_RE = re.compile(r"^[\d\[\]{}()|,^$\-]+$")

_PROBE_LIMIT = 10**12


def _strip_regex_shell(value):
    """Peel (?s)-style flags, ^...$ anchors, and one (?:...)/(...) wrapper."""
    body = _FLAG_PREFIX_RE.sub("", value.strip())
    if body.startswith("^") and body.endswith("$"):
        body = body[1:-1]
    for prefix in ("(?:", "("):
        if body.startswith(prefix) and body.endswith(")"):
            inner = body[len(prefix):-1]
            # Only unwrap if the parentheses actually enclose the whole body.
            depth = 0
            balanced = True
            for ch in inner:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth < 0:
                        balanced = False
                        break
            if balanced and depth == 0:
                body = inner
                break
    return body


def _split_alternation(body):
    """Top-level split on | respecting parentheses."""
    parts = []
    depth = 0
    current = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _decode_int_alternation(parts):
    values = sorted(int(p) for p in parts)
    if len(values) > 2 and values == list(range(values[0], values[-1] + 1)):
        return f"{values[0]} to {values[-1]}"
    return "one of: " + ", ".join(str(v) for v in values)


def _decode_threshold(pattern):
    """Infer 'N or greater' for monotone numeric regexes by probing."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None

    def accepts(n):
        return compiled.fullmatch(str(n)) is not None

    # Find any accepted power of ten.
    probe = 1
    while probe < _PROBE_LIMIT and not accepts(probe):
        probe *= 10
    if probe >= _PROBE_LIMIT:
        return None

    # Binary search the smallest accepted value below that power.
    low, high = probe // 10, probe
    while low < high:
        mid = (low + high) // 2
        if accepts(mid):
            high = mid
        else:
            low = mid + 1
    minimum = low

    # Monotone-threshold sanity: everything from the minimum up accepts,
    # everything just below rejects.
    checks_up = (minimum, minimum + 1, minimum * 3 + 1, minimum * 10)
    if not all(accepts(n) for n in checks_up):
        return None
    if minimum > 0 and accepts(minimum - 1):
        return None
    return f"{minimum} or greater"


def _unescape_literal(text):
    return re.sub(r"\\(.)", r"\1", text).strip()


def decode_expected(raw):
    """Best-effort human rendering of an expected value; raw if unrecognized."""
    if raw is None:
        return ""
    value = str(raw).strip()
    if not value:
        return value

    # Tenable numeric range: [1..365]
    range_match = _TENABLE_RANGE_RE.match(value)
    if range_match:
        return f"{range_match.group(1)} to {range_match.group(2)}"

    # Audit-OR syntax: Disabled" || "Not Found  /  Success" ||"Success and Failure
    if "||" in value and not value.lstrip().startswith(("^", "(", "(?")):
        parts = [p.strip().strip('"') for p in _AUDIT_OR_SPLIT_RE.split(value)]
        parts = [p for p in parts if p]
        if len(parts) > 1 and all(_LITERAL_ALT_RE.match(p) for p in parts):
            return " or ".join(parts)

    # Alternation of fully anchored groups: (^A$)|(^A, B$)
    anchored = _ANCHORED_GROUP_ALT_RE.match(value)
    if anchored:
        alts = re.findall(r"\(\^(.*?)\$\)", value)
        if all(_LITERAL_ALT_RE.match(a) for a in alts):
            return " or ".join(alts)

    # Lookahead inclusion sets: ^(?=.*X)(?=.*Y)?.*$
    lookaheads = _LOOKAHEAD_RE.findall(value)
    if lookaheads and value.lstrip("^").startswith("(?="):
        required = [_unescape_literal(t) for t, opt in lookaheads if not opt]
        optional = [_unescape_literal(t) for t, opt in lookaheads if opt]
        if required:
            rendered = "includes " + ", ".join(required)
            if optional:
                rendered += " (optional: " + ", ".join(optional) + ")"
            return rendered

    looks_like_regex = value.startswith(("^", "(?", "(^")) and value.rstrip(")").endswith("$")
    if looks_like_regex:
        body = _strip_regex_shell(value)
        parts = [p for p in _split_alternation(body) if p]
        if parts and all(_INT_RE.match(p) for p in parts):
            return _decode_int_alternation(parts)
        if parts and all(
            _LITERAL_ALT_RE.match(_unescape_literal(p)) and not re.search(r"[\[\]{}?*+]", p)
            for p in parts
        ):
            return " or ".join(_unescape_literal(p) for p in parts)
        if _NUMERIC_PATTERN_CHARS_RE.match(body.replace(" ", "")):
            threshold = _decode_threshold(value)
            if threshold:
                return threshold

    return value
