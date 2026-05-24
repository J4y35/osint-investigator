"""Tests for the ``password`` command — pure parsers + hash, no network."""

from __future__ import annotations

from osint_investigator.modules.password_module import (
    parse_pwnedpasswords_range,
    sha1_password,
)

# ── sha1_password ────────────────────────────────────────────────────────────


def test_sha1_password_splits_5_and_35() -> None:
    prefix, suffix = sha1_password("password")
    assert len(prefix) == 5
    assert len(suffix) == 35
    # "password" SHA-1 is well-known: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_sha1_password_is_uppercase_hex() -> None:
    prefix, suffix = sha1_password("hunter2")
    assert prefix.isupper()
    assert suffix.isupper()
    assert all(c in "0123456789ABCDEF" for c in prefix + suffix)


def test_sha1_password_differs_per_input() -> None:
    a = sha1_password("password")
    b = sha1_password("password1")
    assert a != b


# ── parse_pwnedpasswords_range ───────────────────────────────────────────────


def test_parse_finds_breached_password() -> None:
    """Real HIBP range responses look like ``SUFFIX:COUNT`` lines."""
    body = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10402474\r\n"  # SHA1("password")
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:3\r\n"
    )
    assert parse_pwnedpasswords_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 10_402_474


def test_parse_returns_zero_for_unbreached_password() -> None:
    body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n"
    assert parse_pwnedpasswords_range(body, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ") == 0


def test_parse_is_case_insensitive() -> None:
    body = "abc1234567890abc1234567890abc12345:42\r\n"
    # Querier might send uppercase
    assert parse_pwnedpasswords_range(body, "ABC1234567890ABC1234567890ABC12345") == 42


def test_parse_handles_lf_and_crlf_line_endings() -> None:
    body_lf = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\n"
    body_crlf = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\r\n"
    needle = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert parse_pwnedpasswords_range(body_lf, needle) == 5
    assert parse_pwnedpasswords_range(body_crlf, needle) == 5


def test_parse_ignores_blank_and_malformed_lines() -> None:
    body = "\r\ngarbage-no-colon\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\r\n:\r\n  \r\n"
    assert parse_pwnedpasswords_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 7


def test_parse_handles_non_integer_count_gracefully() -> None:
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:not-a-number\r\n"
    # Malformed count -> 0, no exception
    assert parse_pwnedpasswords_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 0


def test_parse_returns_zero_on_empty_body() -> None:
    assert parse_pwnedpasswords_range("", "ANY") == 0
