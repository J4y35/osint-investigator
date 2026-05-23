"""Shared retry helper for outbound HTTP calls.

We retry on the failures that are actually transient — 429 (rate limit),
5xx server errors, network timeouts, and connection errors — and bail
immediately on everything else, so a 404 doesn't cost three round trips.

Tenacity is already a project dependency; this module just wires up a
consistent policy and exposes one async function the source modules can
call instead of ``client.get`` directly.
"""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)


class TransientHTTPError(Exception):
    """Raised inside the retry loop on a retryable HTTP status (429 / 5xx).

    Carries the response so the caller can inspect it when retries are
    exhausted. Intentionally not a public symbol — callers should rely on
    :func:`retrying_get` returning the final response object.
    """

    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        super().__init__(f"transient HTTP {response.status_code}")


def is_retryable_status(status: int) -> bool:
    """True for statuses we treat as transient (worth retrying).

    Specifically 429 (rate limited) and any 5xx. Everything else — including
    404, 403, 401 — is final; retrying won't help.
    """
    return status == 429 or 500 <= status < 600


# Network-layer failures worth retrying. We do *not* retry on
# ``httpx.HTTPStatusError`` (we never call ``raise_for_status``) or generic
# ``Exception`` (would mask real bugs).
_RETRYABLE_EXC: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.NetworkError,
    httpx.RemoteProtocolError,
    TransientHTTPError,
)


async def retrying_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_attempts: int = 3,
    initial_backoff: float = 0.5,
    max_backoff: float = 8.0,
    **kwargs: Any,
) -> httpx.Response:
    """``client.get`` with exponential-backoff retry on transient failures.

    Returns the last response — successful or not. Non-transient statuses
    (4xx other than 429, plus any 2xx/3xx) are returned immediately so the
    caller can decide how to handle them. Only timeouts, network errors,
    and 429/5xx responses are retried.

    :param max_attempts: total attempts including the first. ``3`` means one
        original attempt + two retries.
    :param initial_backoff: seconds to wait before the *first* retry.
        Tenacity adds full jitter on top, so actual sleep is
        ``[0, initial_backoff)`` capped by ``max_backoff``.
    """
    last_response: httpx.Response | None = None
    try:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential_jitter(initial=initial_backoff, max=max_backoff),
            retry=retry_if_exception_type(_RETRYABLE_EXC),
            reraise=True,
        ):
            with attempt:
                resp = await client.get(url, **kwargs)
                last_response = resp
                if is_retryable_status(resp.status_code):
                    raise TransientHTTPError(resp)
                return resp
    except TransientHTTPError as exc:
        # All retries exhausted on a transient status — return the response
        # so the caller can surface a clean "rate limited" / "5xx" message
        # instead of treating it like a network failure.
        return exc.response
    except RetryError as exc:
        # Belt-and-suspenders: with `reraise=True` we shouldn't hit this,
        # but if tenacity wraps the exception anyway, unwrap it.
        if isinstance(exc.last_attempt.exception(), TransientHTTPError):
            return exc.last_attempt.exception().response  # type: ignore[union-attr,return-value]
        raise
    # If we somehow exited the loop without returning, last_response will be
    # set; if not, that's a real bug worth raising loudly.
    assert last_response is not None, "retrying_get exited without a response"
    return last_response
