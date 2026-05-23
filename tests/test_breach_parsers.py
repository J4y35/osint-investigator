"""Tests for the pure parsers used by the ``breach`` command.

Exercises HIBP and DDoSecrets response mapping against real captured
fixtures, plus defensive cases for malformed input. No network.
"""

from __future__ import annotations

import json
from pathlib import Path

from osint_investigator.modules.breach_module import (
    BreachHit,
    parse_ddosecrets_html,
    parse_hibp_response,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── HIBP parser ──────────────────────────────────────────────────────────────


def _load_hibp() -> list[dict]:
    return json.loads((FIXTURES / "hibp_account_exists.json").read_text(encoding="utf-8"))


def test_hibp_parser_against_real_response() -> None:
    """The captured fixture is HIBP's documented test account — always has the
    Adobe breach. Validate the full mapping in one go."""
    hits = parse_hibp_response(_load_hibp())
    assert len(hits) == 1
    hit = hits[0]
    assert isinstance(hit, BreachHit)
    assert hit.source == "HIBP"
    assert hit.name == "Adobe"
    assert hit.date == "2013-10-04"
    assert hit.description and "Adobe" in hit.description
    assert hit.url == "https://haveibeenpwned.com/PwnedWebsites#Adobe"
    # DataClasses lives in extra — verify it round-trips as a list.
    assert isinstance(hit.extra.get("data_classes"), list)
    assert hit.extra["data_classes"], "expected non-empty data classes for Adobe breach"


def test_hibp_parser_handles_empty_list() -> None:
    assert parse_hibp_response([]) == []


def test_hibp_parser_handles_none_payload() -> None:
    """Defensive: the wrapper sometimes hands us None on a 404 path."""
    assert parse_hibp_response(None) == []  # type: ignore[arg-type]


def test_hibp_parser_tolerates_missing_fields() -> None:
    """A breach object missing optional fields should still yield a hit."""
    hits = parse_hibp_response([{"Name": "Sparse"}])
    assert len(hits) == 1
    assert hits[0].name == "Sparse"
    assert hits[0].date is None
    assert hits[0].description is None
    assert hits[0].extra["data_classes"] == []
    # URL is built from Name even when Name is the only field present.
    assert hits[0].url == "https://haveibeenpwned.com/PwnedWebsites#Sparse"


def test_hibp_parser_defaults_unnamed_breach() -> None:
    """A breach with no ``Name`` should not crash — falls back to '?'."""
    hits = parse_hibp_response([{}])
    assert hits[0].name == "?"


# ── DDoSecrets parser ────────────────────────────────────────────────────────


def _load_ddosecrets() -> str:
    return (FIXTURES / "ddosecrets_recent.html").read_text(encoding="utf-8")


def test_ddosecrets_parser_finds_articles_by_substring() -> None:
    """``Palo Alto`` is a long-running article in the fixture's catalogue.

    If you re-capture the fixture and this substring no longer matches,
    pick another query that *does* exist in the new capture.
    """
    hits = parse_ddosecrets_html(_load_ddosecrets(), "palo alto")
    assert hits, "expected at least one 'palo alto' article in the fixture"
    assert all(h.source == "DDoSecrets" for h in hits)
    assert all("palo alto" in h.name.lower() for h in hits)
    # URL is built from the relative href.
    assert all((h.url or "").startswith("https://ddosecrets.org/article/") for h in hits)


def test_ddosecrets_parser_is_case_insensitive() -> None:
    upper = parse_ddosecrets_html(_load_ddosecrets(), "PALO ALTO")
    lower = parse_ddosecrets_html(_load_ddosecrets(), "palo alto")
    assert {h.name for h in upper} == {h.name for h in lower}


def test_ddosecrets_parser_returns_empty_for_no_match() -> None:
    assert parse_ddosecrets_html(_load_ddosecrets(), "zzz-no-such-article-xyz") == []


def test_ddosecrets_parser_returns_empty_for_blank_query() -> None:
    """Empty query mustn't return the entire catalogue."""
    assert parse_ddosecrets_html(_load_ddosecrets(), "") == []
    assert parse_ddosecrets_html(_load_ddosecrets(), "   ") == []


def test_ddosecrets_parser_dedupes_by_href() -> None:
    """Each article appears twice in the markup (title + 'Read more')."""
    html = """
    <a href="/article/leak-one">Leak One Title</a>
    <a href="/article/leak-one">Read more</a>
    <a href="/article/leak-two">Leak Two Title</a>
    <a href="/article/leak-two">Read more</a>
    """
    hits = parse_ddosecrets_html(html, "leak")
    names = [h.name for h in hits]
    assert names == ["Leak One Title", "Leak Two Title"]


def test_ddosecrets_parser_ignores_non_article_anchors() -> None:
    """Anchors not pointing at ``/article/`` shouldn't be considered."""
    html = """
    <a href="/article/keep">Keep Me</a>
    <a href="/about">Don't Keep Me</a>
    <a href="https://example.com/article/keep">Don't Keep External</a>
    """
    hits = parse_ddosecrets_html(html, "keep")
    assert [h.name for h in hits] == ["Keep Me"]
