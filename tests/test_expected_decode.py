"""decode_expected(): regex/encoded expectations render as policy meaning.

Patterns pinned to real values observed in the HTH baselines and CIS files.
"""

from pysc.library.expected import decode_expected


def test_plain_values_pass_through():
    assert decode_expected("60") == "60"
    assert decode_expected("Disabled") == "Disabled"
    assert decode_expected("Administrators") == "Administrators"
    assert decode_expected("") == ""
    assert decode_expected(None) == ""


def test_tenable_range():
    assert decode_expected("[1..365]") == "1 to 365"
    assert decode_expected("[14..128]") == "14 to 128"


def test_audit_or_syntax():
    assert decode_expected('Disabled" || "Not Found') == "Disabled or Not Found"
    assert (
        decode_expected('Success" ||"Success and Failure')
        == "Success or Success and Failure"
    )


def test_integer_alternation_range():
    days = "^(" + "|".join(str(n) for n in range(1, 31)) + ")$"
    assert decode_expected(days) == "1 to 30"
    assert decode_expected("^(?:1|2|3)$") == "1 to 3"
    assert decode_expected("^(0|5|10)$") == "one of: 0, 5, 10"


def test_literal_alternation():
    assert (
        decode_expected(r"^(Success|Success\ and\ Failure)$")
        == "Success or Success and Failure"
    )
    assert (
        decode_expected(r"(?s)^(?:Failure|Success\ and\ Failure)$")
        == "Failure or Success and Failure"
    )


def test_anchored_group_alternation():
    assert (
        decode_expected("(^S-1-5-32-544$)|(^S-1-5-32-544, S-1-5-83-0$)")
        == "S-1-5-32-544 or S-1-5-32-544, S-1-5-83-0"
    )


def test_numeric_threshold_probing():
    maxsize_32768 = (
        "^([1-9][0-9]{5,}|[4-9][0-9]{4}|3[3-9][0-9]{3}|32[8-9][0-9]{2}"
        "|327[7-9][0-9]{1}|3276[8-9])$"
    )
    maxsize_196608 = (
        "^([1-9][0-9]{6,}|[2-9][0-9]{5}|19[7-9][0-9]{3}|196[7-9][0-9]{2}"
        "|1966[1-9][0-9]{1}|19660[8-9])$"
    )
    assert decode_expected(maxsize_32768) == "32768 or greater"
    assert decode_expected(maxsize_196608) == "196608 or greater"


def test_lookahead_inclusion():
    assert (
        decode_expected(r"^(?=.*S-1-5-32-544)(?=.*S-1-5-6)?(?=.*S-1-5-19)?(?=.*S-1-5-20)?.*$")
        == "includes S-1-5-32-544 (optional: S-1-5-6, S-1-5-19, S-1-5-20)"
    )


def test_unrecognized_returns_raw():
    gnarly = r"^(?i)some[Cc]omplex.*(pattern){2,3}$"
    assert decode_expected(gnarly) == gnarly
