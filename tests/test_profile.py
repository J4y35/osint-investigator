"""Tests for the ``profile`` aggregator's rendering + serialisation helpers.

The orchestrator itself (``_run_profile``) calls into other modules'
network code and is integration-tested by the smoke checks. Here we
focus on the pure transforms — Markdown rendering and JSON-safe
serialisation — which is what tends to regress when the upstream
modules change shape.
"""

from __future__ import annotations

from osint_investigator.modules.breach_module import BreachHit, BreachResult
from osint_investigator.modules.domain_module import SectionResult as DomainSectionResult
from osint_investigator.modules.person_module import PersonHit, SourceResult
from osint_investigator.modules.profile_module import (
    _md_breach,
    _md_domain,
    _md_email_holehe,
    _md_person,
    _md_username,
    _render_markdown,
    _serialise_sections,
)
from osint_investigator.modules.username_module import ProbeResult

# ── Markdown helpers ─────────────────────────────────────────────────────────


def test_md_email_holehe_no_accounts() -> None:
    md = _md_email_holehe([{"name": "Site1", "exists": False}, {"name": "Site2", "exists": None}])
    assert "0 found of 2 probed" in md
    assert "No accounts identified" in md


def test_md_email_holehe_with_accounts() -> None:
    md = _md_email_holehe(
        [
            {"name": "Adobe", "exists": True, "emailrecovery": "a@b", "phoneNumber": "+1"},
            {"name": "Twitter", "exists": False},
        ]
    )
    assert "1 found of 2 probed" in md
    assert "| Adobe |" in md
    # Non-exists rows must NOT show up in the table.
    assert "Twitter" not in md


def test_md_breach_renders_status_and_hits() -> None:
    results = [
        BreachResult(
            "hibp",
            "ok",
            hits=[BreachHit(source="HIBP", name="Adobe", date="2013-10-04")],
            message="1 breach(es) found",
        ),
        BreachResult("ddosecrets", "empty", message="no recent articles matched"),
    ]
    md = _md_breach(results)
    assert "1 hit(s)" in md
    assert "**hibp**" in md and "`ok`" in md
    assert "**ddosecrets**" in md and "`empty`" in md
    assert "Adobe" in md
    assert "2013-10-04" in md


def test_md_username_filters_to_taken() -> None:
    rows = [
        ProbeResult(site="GitHub", url="https://github.com/x", exists=True, status=200),
        ProbeResult(site="GitLab", url="https://gitlab.com/x", exists=False, status=404),
        ProbeResult(site="Twitch", url="https://twitch.tv/x", exists=None, status=None),
    ]
    md = _md_username(rows)
    assert "3 sites — 1 taken" in md
    assert "GitHub" in md
    # Non-taken sites are not rendered.
    assert "GitLab" not in md
    assert "Twitch" not in md


def test_md_username_empty_when_none_taken() -> None:
    rows = [ProbeResult(site="GitHub", url="https://github.com/x", exists=False, status=404)]
    md = _md_username(rows)
    assert "Handle not found" in md


def test_md_person_truncates_at_25_hits() -> None:
    """Long CourtListener result sets get truncated for report readability."""
    hits = [
        PersonHit(source="courtlistener.com", name=f"Case {i}", location="Court X")
        for i in range(40)
    ]
    results = [SourceResult("courtlistener", "ok", hits=hits, message=f"{len(hits)} hits")]
    md = _md_person(results)
    assert "40 hit(s)" in md
    assert "Case 0" in md
    assert "Case 24" in md
    # Case 25 onwards are truncated.
    assert "Case 25" not in md
    assert "15 more hits truncated" in md


def test_md_domain_renders_rdap_dns_subdomains() -> None:
    results = [
        DomainSectionResult(
            "rdap",
            "ok",
            payload={
                "registrar": "Example Registrar",
                "registration_date": "2010-01-01",
                "expiration_date": "2030-01-01",
                "status": ["clientTransferProhibited"],
                "nameservers": ["ns1.example.com", "ns2.example.com"],
            },
        ),
        DomainSectionResult(
            "dns",
            "ok",
            payload={"records": {"A": ["1.2.3.4"], "MX": ["10 mail.example.com."]}},
        ),
        DomainSectionResult(
            "subdomains",
            "ok",
            payload={"count": 2, "subdomains": ["api.example.com", "www.example.com"]},
            message="2 unique names found",
        ),
    ]
    md = _md_domain(results)
    assert "Example Registrar" in md
    assert "2010-01-01" in md
    assert "ns1.example.com" in md
    assert "1.2.3.4" in md
    assert "10 mail.example.com." in md
    assert "api.example.com" in md
    assert "2 unique names found" in md


# ── _serialise_sections ──────────────────────────────────────────────────────


def test_serialise_sections_unwraps_dataclasses() -> None:
    sections = {
        "person": [
            SourceResult(
                "courtlistener",
                "ok",
                hits=[PersonHit(source="x", name="A v B")],
                message="1 hit",
            )
        ],
    }
    out = _serialise_sections(sections)
    assert isinstance(out["person"], list)
    assert out["person"][0]["source"] == "courtlistener"
    assert out["person"][0]["hits"][0]["name"] == "A v B"


def test_serialise_sections_captures_exceptions_as_error_dict() -> None:
    sections = {"domain": RuntimeError("crt.sh down")}
    out = _serialise_sections(sections)
    assert out["domain"] == {"error": "RuntimeError: crt.sh down"}


def test_serialise_sections_passes_through_plain_dicts() -> None:
    sections = {"email_holehe": [{"name": "Adobe", "exists": True}]}
    out = _serialise_sections(sections)
    # Plain dicts (Holehe rows) come through unchanged.
    assert out["email_holehe"] == [{"name": "Adobe", "exists": True}]


# ── _render_markdown ─────────────────────────────────────────────────────────


def test_render_markdown_includes_all_sections() -> None:
    query = {"email": "x@y.com", "username": "alice"}
    sections = {
        "email_holehe": [{"name": "Adobe", "exists": True}],
        "email_breach": [BreachResult("hibp", "ok", hits=[BreachHit(source="HIBP", name="Adobe")])],
        "username": [
            ProbeResult(site="GitHub", url="https://github.com/alice", exists=True, status=200)
        ],
    }
    md = _render_markdown(query, sections)
    assert md.startswith("# Profile report")
    assert "alice" in md
    assert "Adobe" in md
    assert "GitHub" in md


def test_render_markdown_handles_exception_in_section() -> None:
    """An exception in one section shouldn't break the whole report."""
    query = {"email": "x@y"}
    sections = {"email_holehe": RuntimeError("Holehe import failed")}
    md = _render_markdown(query, sections)
    assert "RuntimeError" in md
    assert "Holehe import failed" in md
