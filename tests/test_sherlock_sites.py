"""Tests for the Sherlock catalogue loader and site-selection helpers.

These tests never touch the network. They exercise parsing, normalisation,
and the public selection API (curated default vs. ``--all`` vs. ``--site``,
NSFW filtering, ``--top`` truncation).
"""

from __future__ import annotations

import pytest

from osint_investigator.modules.sherlock_sites import (
    DEFAULT_CURATED,
    SiteProbe,
    _build_probe,
    _coerce_error_codes,
    _coerce_error_messages,
    load_all_sites,
    select_sites,
)

# ── Loader -------------------------------------------------------------------


def test_load_all_sites_is_non_empty_and_tuple() -> None:
    sites = load_all_sites()
    assert isinstance(sites, tuple)
    # Sherlock's catalogue ships hundreds of sites; if this drops to single
    # digits the bundled data file is almost certainly corrupted.
    assert len(sites) > 100
    assert all(isinstance(s, SiteProbe) for s in sites)


def test_load_all_sites_is_cached() -> None:
    """Repeated calls return the exact same tuple object (lru_cache hit)."""
    assert load_all_sites() is load_all_sites()


def test_loaded_sites_have_valid_probe_urls() -> None:
    """The URL we actually GET must contain a username placeholder.

    Sherlock sometimes points ``url`` at a site homepage when ``urlProbe`` is
    the real per-user endpoint, so we only enforce the placeholder on
    ``probe_url_template``. Entries where neither has ``{}`` are dropped by
    :func:`_build_probe`.
    """
    for s in load_all_sites():
        assert "{}" in s.probe_url_template, s.name
        assert s.error_type in {"status_code", "message", "response_url"}


def test_message_probes_have_at_least_one_error_message() -> None:
    """If errorType is ``message``, we must have markers to look for."""
    for s in load_all_sites():
        if s.error_type == "message":
            assert s.error_messages, f"{s.name} declares message-mode with no markers"


def test_response_url_probes_have_an_error_url() -> None:
    for s in load_all_sites():
        if s.error_type == "response_url":
            assert s.error_url, f"{s.name} declares response_url-mode with no errorUrl"


# ── Helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, ()),
        ("not found", ("not found",)),
        (["a", "b"], ("a", "b")),
        ([1, "ok"], ("1", "ok")),  # ints are stringified — schema is forgiving
        (42, ()),  # garbage shapes degrade silently rather than raising
    ],
)
def test_coerce_error_messages(raw: object, expected: tuple[str, ...]) -> None:
    assert _coerce_error_messages(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, ()), (404, (404,)), ([404, 410], (404, 410)), ([404, "x"], (404,))],
)
def test_coerce_error_codes(raw: object, expected: tuple[int, ...]) -> None:
    assert _coerce_error_codes(raw) == expected


def test_build_probe_skips_post_only_sites() -> None:
    """POST sites aren't yet supported by our probe runner — skip cleanly."""
    entry = {
        "url": "https://example.com/{}",
        "urlMain": "https://example.com/",
        "errorType": "status_code",
        "request_method": "POST",
    }
    assert _build_probe("Example", entry) is None


def test_build_probe_skips_unknown_error_type() -> None:
    entry = {
        "url": "https://example.com/{}",
        "urlMain": "https://example.com/",
        "errorType": "magic",  # not in Sherlock's documented enum
    }
    assert _build_probe("Example", entry) is None


def test_build_probe_uses_url_probe_override() -> None:
    """When ``urlProbe`` is set we should GET it but still surface ``url``."""
    entry = {
        "url": "https://example.com/profile/{}",
        "urlProbe": "https://example.com/api/users/{}",
        "urlMain": "https://example.com/",
        "errorType": "status_code",
    }
    probe = _build_probe("Example", entry)
    assert probe is not None
    assert probe.profile_url("alice") == "https://example.com/profile/alice"
    assert probe.probe_url("alice") == "https://example.com/api/users/alice"


def test_build_probe_swallows_bad_regex() -> None:
    """A broken ``regexCheck`` shouldn't drop the entire site — just the regex."""
    entry = {
        "url": "https://example.com/{}",
        "urlMain": "https://example.com/",
        "errorType": "status_code",
        "regexCheck": "(unclosed",  # invalid regex
    }
    probe = _build_probe("Example", entry)
    assert probe is not None
    assert probe.regex_check is None


# ── Selection ----------------------------------------------------------------


def test_select_sites_default_uses_curated_list() -> None:
    chosen = select_sites()
    names_lower = {s.name.lower() for s in chosen}
    # Default must be non-empty and a subset of the curated set.
    assert chosen
    assert names_lower.issubset({n.lower() for n in DEFAULT_CURATED})
    # And no NSFW leaks through by default.
    assert not any(s.nsfw for s in chosen)


def test_select_sites_all_returns_more_than_curated() -> None:
    all_chosen = select_sites(all_sites=True)
    curated_chosen = select_sites()
    assert len(all_chosen) > len(curated_chosen)


def test_select_sites_top_truncates() -> None:
    five = select_sites(all_sites=True, top=5)
    assert len(five) == 5


def test_select_sites_site_filter_is_case_insensitive_substring() -> None:
    # Every supportable site name containing "git" should come back.
    chosen = select_sites(site_filters=("git",))
    assert chosen
    assert all("git" in s.name.lower() for s in chosen)
    # And it must include the canonical "GitHub" entry.
    assert any(s.name == "GitHub" for s in chosen)


def test_select_sites_include_nsfw_flag() -> None:
    """NSFW sites are excluded by default and included when asked."""
    without = select_sites(all_sites=True)
    with_nsfw = select_sites(all_sites=True, include_nsfw=True)
    assert len(with_nsfw) >= len(without)
    # The bundled catalogue currently flags ~19 NSFW sites — assert at least
    # one is present when --include-nsfw is set.
    assert any(s.nsfw for s in with_nsfw)
    assert not any(s.nsfw for s in without)


def test_select_sites_returns_empty_list_for_unmatched_filter() -> None:
    assert select_sites(site_filters=("this-string-matches-nothing-xyz",)) == []
