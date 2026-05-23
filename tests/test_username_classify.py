"""Unit tests for the response → exists classifier used by the username probe.

These tests construct fake :class:`httpx.Response` objects directly so we
can hammer every Sherlock error-type branch without going near the network.
"""

from __future__ import annotations

import httpx
import pytest

from osint_investigator.modules.sherlock_sites import SiteProbe
from osint_investigator.modules.username_module import _classify


def _probe(
    *,
    error_type: str,
    error_messages: tuple[str, ...] = (),
    error_url: str | None = None,
    error_status_codes: tuple[int, ...] = (),
) -> SiteProbe:
    return SiteProbe(
        name="Test",
        url_template="https://example.com/{}",
        probe_url_template="https://example.com/{}",
        error_type=error_type,  # type: ignore[arg-type]
        error_messages=error_messages,
        error_url=error_url,
        error_status_codes=error_status_codes,
    )


def _resp(status: int = 200, text: str = "", url: str = "https://example.com/u") -> httpx.Response:
    return httpx.Response(
        status_code=status,
        text=text,
        request=httpx.Request("GET", url),
    )


# ── status_code mode ─────────────────────────────────────────────────────────


def test_status_code_200_means_exists() -> None:
    assert _classify(_probe(error_type="status_code"), _resp(200)) is True


def test_status_code_404_means_free() -> None:
    assert _classify(_probe(error_type="status_code"), _resp(404)) is False


def test_status_code_5xx_is_ambiguous() -> None:
    assert _classify(_probe(error_type="status_code"), _resp(503)) is None


def test_status_code_with_explicit_error_code_flips_meaning() -> None:
    """When errorCode is set, that code means *not found* and 200/3xx means found."""
    probe = _probe(error_type="status_code", error_status_codes=(410,))
    assert _classify(probe, _resp(410)) is False
    assert _classify(probe, _resp(200)) is True


# ── message mode ─────────────────────────────────────────────────────────────


def test_message_marker_present_means_free() -> None:
    probe = _probe(error_type="message", error_messages=("No such user",))
    assert _classify(probe, _resp(200, text="<h1>No such user</h1>")) is False


def test_message_marker_absent_on_200_means_exists() -> None:
    probe = _probe(error_type="message", error_messages=("No such user",))
    assert _classify(probe, _resp(200, text="<h1>Welcome, Alice</h1>")) is True


def test_message_marker_absent_on_non_200_is_ambiguous() -> None:
    """A 500 without the marker shouldn't be reported as "free"."""
    probe = _probe(error_type="message", error_messages=("No such user",))
    assert _classify(probe, _resp(500, text="server error")) is None


def test_message_matches_any_marker_in_list() -> None:
    probe = _probe(
        error_type="message",
        error_messages=("first marker", "second marker"),
    )
    assert _classify(probe, _resp(200, text="...second marker...")) is False


# ── response_url mode ────────────────────────────────────────────────────────


def test_response_url_exact_match_means_free() -> None:
    """Final URL equals the error URL (modulo trailing slash) → not found."""
    probe = _probe(error_type="response_url", error_url="https://example.com/")
    assert _classify(probe, _resp(200, url="https://example.com/")) is False
    assert _classify(probe, _resp(200, url="https://example.com")) is False  # no slash


def test_response_url_non_match_means_exists() -> None:
    """A URL *under* the error URL (e.g. /alice) must NOT be classified as free."""
    probe = _probe(error_type="response_url", error_url="https://example.com/")
    assert _classify(probe, _resp(200, url="https://example.com/alice")) is True


def test_response_url_specific_error_path_match() -> None:
    probe = _probe(error_type="response_url", error_url="https://example.com/not-found")
    assert _classify(probe, _resp(200, url="https://example.com/not-found")) is False
    assert _classify(probe, _resp(200, url="https://example.com/profile/alice")) is True


# ── meta ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad_type", ["bogus", "", None])
def test_unknown_error_type_returns_none(bad_type: object) -> None:
    """Defensive: a non-canonical error type yields ``None`` rather than raising."""
    probe = SiteProbe(
        name="Test",
        url_template="https://example.com/{}",
        probe_url_template="https://example.com/{}",
        error_type=bad_type,  # type: ignore[arg-type]
    )
    assert _classify(probe, _resp(200)) is None
