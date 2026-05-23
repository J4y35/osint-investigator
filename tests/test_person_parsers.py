"""Tests for the pure parsers used by the ``person`` command.

These exercise the HTML/JSON → :class:`PersonHit` mapping using saved
fixtures, so they run without a browser and without hitting the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from osint_investigator.modules.person_module import (
    is_cloudflare_interstitial,
    parse_courtlistener_response,
    parse_cyberbackgroundchecks_html,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── Cloudflare interstitial detector ─────────────────────────────────────────


def test_cloudflare_interstitial_detected_from_real_capture() -> None:
    html = (FIXTURES / "cyberbackgroundchecks_cloudflare.html").read_text(encoding="utf-8")
    # Real-world capture: page title is "Just a moment..."
    assert is_cloudflare_interstitial(html, title="Just a moment...")


def test_cloudflare_interstitial_not_falsely_flagged_on_normal_page() -> None:
    html = "<html><body><h1>People search</h1><div class='record'>x</div></body></html>"
    assert not is_cloudflare_interstitial(html, title="Search results")


def test_cloudflare_interstitial_requires_multiple_markers() -> None:
    """A single marker in unrelated content shouldn't trigger the detector."""
    # Only one marker present ("Just a moment...") — not enough.
    html = "<html><body>Welcome back. Just a moment... we'll be right there!</body></html>"
    assert not is_cloudflare_interstitial(html, title="Home")


# ── cyberbackgroundchecks HTML parser ────────────────────────────────────────


def test_cbc_parser_returns_empty_for_cloudflare_page() -> None:
    """The challenge page has no result cards — parser must not invent any."""
    html = (FIXTURES / "cyberbackgroundchecks_cloudflare.html").read_text(encoding="utf-8")
    assert parse_cyberbackgroundchecks_html(html, "John", "Smith") == []


def test_cbc_parser_extracts_cards_from_synthetic_markup() -> None:
    """Construct a small synthetic results page mirroring the assumed schema."""
    html = """
    <html><body>
      <div class="record">
        <h2 class="name">John A Smith</h2>
        <span class="age">42</span>
        <div class="address">Austin, TX</div>
      </div>
      <div class="record">
        <h2 class="name">John B Smith</h2>
        <span class="age">61</span>
        <div class="location">Portland, OR</div>
      </div>
    </body></html>
    """
    hits = parse_cyberbackgroundchecks_html(html, "John", "Smith")
    assert len(hits) == 2
    assert hits[0].name == "John A Smith"
    assert hits[0].age == "42"
    assert hits[0].location == "Austin, TX"
    assert hits[1].location == "Portland, OR"
    assert all(h.source == "cyberbackgroundchecks.com" for h in hits)


# ── CourtListener JSON parser ────────────────────────────────────────────────


def test_courtlistener_parser_against_real_response() -> None:
    payload = json.loads((FIXTURES / "courtlistener_recap_sample.json").read_text(encoding="utf-8"))
    hits = parse_courtlistener_response(payload)
    # Fixture was trimmed to 3 results.
    assert len(hits) == 3
    assert all(h.source == "courtlistener.com" for h in hits)
    # Every hit has *some* case name and an absolute URL on courtlistener.com.
    for h in hits:
        assert h.name and h.name != "unknown case"
        assert h.url and h.url.startswith("https://www.courtlistener.com/")
    # Court information shows up as the `location` field for table rendering.
    assert any(h.location for h in hits)
    # Docket numbers and filing dates land in `extra`.
    assert any("docket_number" in (h.extra or {}) or "date_filed" in (h.extra or {}) for h in hits)


def test_courtlistener_parser_handles_missing_results_key() -> None:
    """Defensive: an API response with no ``results`` shouldn't raise."""
    assert parse_courtlistener_response({}) == []
    assert parse_courtlistener_response({"results": None}) == []


def test_courtlistener_parser_handles_minimal_entry() -> None:
    """A docket missing optional fields should still yield a hit, gracefully."""
    payload = {"results": [{"caseName": "Doe v. Roe"}]}
    hits = parse_courtlistener_response(payload)
    assert len(hits) == 1
    assert hits[0].name == "Doe v. Roe"
    assert hits[0].url is None
    assert hits[0].location is None


@pytest.mark.parametrize(
    ("entry", "expected_name"),
    [
        ({"caseName": "A v B"}, "A v B"),
        ({"caseNameShort": "Short"}, "Short"),
        ({}, "unknown case"),
    ],
)
def test_courtlistener_parser_name_fallback(entry: dict[str, str], expected_name: str) -> None:
    hits = parse_courtlistener_response({"results": [entry]})
    assert hits[0].name == expected_name
