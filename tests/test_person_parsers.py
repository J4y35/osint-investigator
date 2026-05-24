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
    parse_edgar_response,
    parse_fec_response,
    parse_opencorporates_response,
    parse_trade_gov_csl_response,
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


# ── OpenCorporates parser ────────────────────────────────────────────────────


def test_opencorporates_parser_against_fixture() -> None:
    payload = json.loads((FIXTURES / "opencorporates_officers.json").read_text(encoding="utf-8"))
    hits = parse_opencorporates_response(payload)
    assert len(hits) == 3
    assert all(h.source == "opencorporates.com" for h in hits)
    # Officer name preserved as-given (OpenCorporates uses "Last, First" form).
    assert hits[0].name.startswith("Sotomayor")
    # Company + position + jurisdiction land in `extra`.
    assert hits[0].extra["company"] == "Example Holdings LLC"
    assert hits[0].extra["position"] == "director"
    assert hits[0].extra["jurisdiction"] == "us_ny"
    assert hits[0].location == "us_ny"
    assert hits[0].url == "https://opencorporates.com/officers/1234567"
    # Inactive officership keeps end_date in extra.
    assert hits[1].extra["end_date"] == "2012-01-31"


def test_opencorporates_parser_handles_empty_results() -> None:
    assert parse_opencorporates_response({}) == []
    assert parse_opencorporates_response({"results": {}}) == []
    assert parse_opencorporates_response({"results": {"officers": []}}) == []


def test_opencorporates_parser_tolerates_missing_company() -> None:
    payload = {"results": {"officers": [{"officer": {"name": "Sparse Person"}}]}}
    hits = parse_opencorporates_response(payload)
    assert len(hits) == 1
    assert hits[0].name == "Sparse Person"
    assert hits[0].location is None
    assert "company" not in hits[0].extra


# ── FEC donor parser ─────────────────────────────────────────────────────────


def test_fec_parser_against_fixture() -> None:
    payload = json.loads((FIXTURES / "fec_donor_search.json").read_text(encoding="utf-8"))
    hits = parse_fec_response(payload)
    assert len(hits) == 3
    assert all(h.source == "fec.gov" for h in hits)
    # Location = "City, ST" when both city and state are present.
    assert hits[0].location == "AUSTIN, TX"
    # Money + date + employer/occupation surface in extra.
    assert hits[0].extra["amount_usd"] == 250.0
    assert hits[0].extra["date"] == "2024-09-15"
    assert hits[0].extra["employer"] == "ACME CORP"
    assert hits[0].extra["occupation"] == "ENGINEER"
    assert hits[0].extra["committee"] == "EXAMPLE FOR CONGRESS"
    # PDF link is preserved.
    assert hits[0].url and hits[0].url.startswith("https://docquery.fec.gov/")
    # Older entries with `committee_name` (no nested `committee.name`) still work.
    assert hits[2].extra["committee"] == "Senate Committee X"


def test_fec_parser_handles_empty_results() -> None:
    assert parse_fec_response({}) == []
    assert parse_fec_response({"results": []}) == []


def test_fec_parser_handles_zero_amount() -> None:
    """A 0.0 contribution is uncommon but valid — must not be elided as falsy."""
    payload = {
        "results": [
            {"contributor_name": "X Y", "contribution_receipt_amount": 0.0},
        ]
    }
    hits = parse_fec_response(payload)
    # We do treat 0.0 as a real value (the `is not None` guard).
    assert hits[0].extra["amount_usd"] == 0.0


# ── SEC EDGAR parser ─────────────────────────────────────────────────────────


def test_edgar_parser_against_real_fixture() -> None:
    payload = json.loads((FIXTURES / "edgar_sotomayor.json").read_text(encoding="utf-8"))
    hits = parse_edgar_response(payload)
    assert hits, "expected at least one EDGAR hit in the fixture"
    assert all(h.source == "sec.gov/EDGAR" for h in hits)
    # display_names line is the canonical company label.
    assert any("PPL Corp" in h.name for h in hits)
    # File metadata lives in extra.
    assert all(("form" in h.extra or "file_date" in h.extra) for h in hits)
    # Filing index URL is constructed correctly when CIK and adsh are present.
    with_url = [h for h in hits if h.url]
    assert with_url
    for h in with_url:
        assert h.url.startswith("https://www.sec.gov/Archives/edgar/data/")
        assert h.url.endswith("-index.htm")


def test_edgar_parser_handles_empty_payload() -> None:
    assert parse_edgar_response({}) == []
    assert parse_edgar_response({"hits": {}}) == []
    assert parse_edgar_response({"hits": {"hits": []}}) == []


def test_edgar_parser_tolerates_missing_cik_or_adsh() -> None:
    """Entries without CIK/adsh shouldn't crash — just yield a URL-less hit."""
    payload = {
        "hits": {"hits": [{"_source": {"display_names": ["Mystery Filing"], "form": "8-K"}}]}
    }
    hits = parse_edgar_response(payload)
    assert len(hits) == 1
    assert hits[0].name == "Mystery Filing"
    assert hits[0].url is None
    assert hits[0].extra["form"] == "8-K"


# ── Trade.gov consolidated-screening-list parser ─────────────────────────────


def test_trade_gov_csl_parser_against_fixture() -> None:
    payload = json.loads((FIXTURES / "trade_gov_csl.json").read_text(encoding="utf-8"))
    hits = parse_trade_gov_csl_response(payload)
    assert len(hits) == 2
    # Source is decorated with the originating list name for clarity.
    assert "Specially Designated Nationals" in hits[0].source
    assert "Entity List" in hits[1].source
    # First entry: location pieced from city + country.
    assert hits[0].location == "Tehran, Iran"
    # Sanctions programs surfaced as a list in extra.
    assert hits[0].extra["programs"] == ["IRAN", "SDGT"]
    assert hits[0].extra["citizenships"] == ["Country X"]
    # Entity-type entries with country-only addresses keep that as location.
    assert hits[1].location == "Country Y"
    assert hits[1].extra["entity_type"] == "Entity"


def test_trade_gov_csl_parser_handles_empty_results() -> None:
    assert parse_trade_gov_csl_response({}) == []
    assert parse_trade_gov_csl_response({"results": []}) == []


def test_trade_gov_csl_parser_tolerates_missing_addresses() -> None:
    payload = {"results": [{"name": "Stub Entity", "type": "Entity", "source": "Test List"}]}
    hits = parse_trade_gov_csl_response(payload)
    assert len(hits) == 1
    assert hits[0].name == "Stub Entity"
    assert hits[0].location is None
    assert "Test List" in hits[0].source
