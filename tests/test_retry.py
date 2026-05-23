"""Tests for the shared retry helper.

We drive ``retrying_get`` against an in-process ``httpx.MockTransport`` so
we control exactly which statuses are returned on which attempts. No
real network, no sleeps that matter (we shrink the backoff to ~0 so the
suite stays fast).
"""

from __future__ import annotations

import httpx
import pytest

from osint_investigator.retry import is_retryable_status, retrying_get

# ── is_retryable_status ──────────────────────────────────────────────────────


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 599])
def test_is_retryable_status_true(status: int) -> None:
    assert is_retryable_status(status)


@pytest.mark.parametrize("status", [200, 201, 301, 400, 401, 403, 404, 422])
def test_is_retryable_status_false(status: int) -> None:
    assert not is_retryable_status(status)


# ── retrying_get behaviour ───────────────────────────────────────────────────


def _make_client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    """Build a real AsyncClient bound to a deterministic mock transport."""
    return httpx.AsyncClient(transport=handler)


async def test_retrying_get_returns_immediately_on_2xx() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="ok")

    async with _make_client(httpx.MockTransport(handler)) as client:
        resp = await retrying_get(client, "https://example.com/")
    assert resp.status_code == 200
    assert calls["n"] == 1, "no retry on a 200 response"


async def test_retrying_get_does_not_retry_on_404() -> None:
    """Non-retryable 4xx codes should return after a single attempt."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    async with _make_client(httpx.MockTransport(handler)) as client:
        resp = await retrying_get(client, "https://example.com/", max_attempts=3)
    assert resp.status_code == 404
    assert calls["n"] == 1


async def test_retrying_get_retries_on_429_then_succeeds() -> None:
    """A 429 followed by a 200 should return the 200 after one retry."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200) if calls["n"] > 1 else httpx.Response(429)

    async with _make_client(httpx.MockTransport(handler)) as client:
        resp = await retrying_get(
            client,
            "https://example.com/",
            max_attempts=3,
            initial_backoff=0.001,
            max_backoff=0.01,
        )
    assert resp.status_code == 200
    assert calls["n"] == 2


async def test_retrying_get_returns_last_response_when_exhausted() -> None:
    """All attempts 5xx → return the final response so caller sees the code."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    async with _make_client(httpx.MockTransport(handler)) as client:
        resp = await retrying_get(
            client,
            "https://example.com/",
            max_attempts=3,
            initial_backoff=0.001,
            max_backoff=0.01,
        )
    assert resp.status_code == 503
    assert calls["n"] == 3


async def test_retrying_get_retries_on_network_error_then_succeeds() -> None:
    """A connect error followed by a 200 should retry to success."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("simulated network blip")
        return httpx.Response(200)

    async with _make_client(httpx.MockTransport(handler)) as client:
        resp = await retrying_get(
            client,
            "https://example.com/",
            max_attempts=3,
            initial_backoff=0.001,
            max_backoff=0.01,
        )
    assert resp.status_code == 200
    assert calls["n"] == 2


async def test_retrying_get_reraises_network_error_when_exhausted() -> None:
    """All attempts raise → the final exception propagates."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("perma-broken")

    async with _make_client(httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ConnectError):
            await retrying_get(
                client,
                "https://example.com/",
                max_attempts=2,
                initial_backoff=0.001,
                max_backoff=0.01,
            )
    assert calls["n"] == 2
