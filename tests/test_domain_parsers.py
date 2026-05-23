"""Tests for the pure parsers used by the ``domain`` command.

Exercises RDAP and crt.sh response mapping against real captured
fixtures, plus the domain validation regex. No network, no DNS.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from osint_investigator.modules.domain_module import (
    is_valid_domain,
    parse_crtsh_response,
    parse_rdap_response,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── Domain validation ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "good",
    [
        "example.com",
        "iana.org",
        "sub.example.co.uk",
        "a-b.c-d.com",
        "xn--80akhbyknj4f.com",  # punycode IDN
    ],
)
def test_is_valid_domain_accepts(good: str) -> None:
    assert is_valid_domain(good)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a domain",
        "-example.com",
        "example-.com",
        "exam_ple.com",
        ".com",
        "com",
        "http://example.com",
        "example..com",
    ],
)
def test_is_valid_domain_rejects(bad: str) -> None:
    assert not is_valid_domain(bad)


# ── RDAP parser ──────────────────────────────────────────────────────────────


def _load_rdap() -> dict:
    return json.loads((FIXTURES / "rdap_iana_org.json").read_text(encoding="utf-8"))


def test_rdap_parser_extracts_registrar() -> None:
    parsed = parse_rdap_response(_load_rdap())
    # iana.org's registrar at capture time was "CSC Corporate Domains, Inc.".
    # We assert it's *some* non-empty string rather than the exact value so
    # the test survives a benign re-registration without going stale.
    assert isinstance(parsed["registrar"], str) and parsed["registrar"]


def test_rdap_parser_extracts_key_dates() -> None:
    parsed = parse_rdap_response(_load_rdap())
    assert parsed["registration_date"].startswith("1995-06-")
    # Expiration falls somewhere in the near future of the capture.
    assert parsed["expiration_date"].startswith("20")
    assert parsed["last_changed"] is not None


def test_rdap_parser_extracts_status_flags() -> None:
    parsed = parse_rdap_response(_load_rdap())
    statuses = parsed["status"]
    assert isinstance(statuses, list)
    assert any("prohibited" in s for s in statuses)


def test_rdap_parser_extracts_and_dedupes_nameservers() -> None:
    parsed = parse_rdap_response(_load_rdap())
    ns = parsed["nameservers"]
    assert len(ns) == len(set(ns)), "nameservers should be deduplicated"
    # All lowercase, fully qualified.
    assert all(n == n.lower() for n in ns)
    assert any("iana" in n for n in ns)


def test_rdap_parser_handles_empty_payload() -> None:
    """An empty dict shouldn't blow up — just yield empty defaults."""
    parsed = parse_rdap_response({})
    assert parsed["registrar"] is None
    assert parsed["registration_date"] is None
    assert parsed["nameservers"] == []
    assert parsed["status"] == []


def test_rdap_parser_handles_missing_vcard() -> None:
    """An entity with role=registrar but no vcardArray must not crash."""
    payload = {"entities": [{"roles": ["registrar"]}]}
    parsed = parse_rdap_response(payload)
    assert parsed["registrar"] is None


def test_rdap_parser_recognises_last_update_event_alias() -> None:
    """The 'last update of RDAP database' event is treated as last_changed."""
    payload = {
        "events": [
            {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"}
        ]
    }
    parsed = parse_rdap_response(payload)
    assert parsed["last_changed"] == "2026-01-01T00:00:00Z"


# ── crt.sh parser ────────────────────────────────────────────────────────────


def test_crtsh_parser_against_real_fixture() -> None:
    payload = json.loads((FIXTURES / "crtsh_iana_org.json").read_text(encoding="utf-8"))
    subs = parse_crtsh_response(payload, "iana.org")
    # The fixture is trimmed to 5 cert rows; expect ≥1 unique subdomain.
    assert subs, "expected at least one subdomain"
    assert subs == sorted(subs), "output should be sorted"
    assert len(subs) == len(set(subs)), "output should be unique"
    assert all(s == "iana.org" or s.endswith(".iana.org") for s in subs)
    assert all(not s.startswith("*") for s in subs), "wildcard prefix stripped"


def test_crtsh_parser_splits_multi_san_entries() -> None:
    """name_value with embedded newlines should expand to one sub per line."""
    payload = [
        {"name_value": "a.example.com\nb.example.com\nexample.com"},
        {"name_value": "c.example.com"},
    ]
    subs = parse_crtsh_response(payload, "example.com")
    assert subs == ["a.example.com", "b.example.com", "c.example.com", "example.com"]


def test_crtsh_parser_filters_out_unrelated_names() -> None:
    """Defensive: crt.sh sometimes returns entries that escape the filter."""
    payload = [{"name_value": "a.example.com\nx.elsewhere.com"}]
    subs = parse_crtsh_response(payload, "example.com")
    assert subs == ["a.example.com"]


def test_crtsh_parser_strips_wildcards() -> None:
    payload = [{"name_value": "*.example.com\n*.api.example.com"}]
    subs = parse_crtsh_response(payload, "example.com")
    assert subs == ["api.example.com", "example.com"]


def test_crtsh_parser_handles_empty_list() -> None:
    assert parse_crtsh_response([], "example.com") == []
