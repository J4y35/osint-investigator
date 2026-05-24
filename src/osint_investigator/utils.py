"""Shared helpers used across CLI modules.

Kept intentionally small — anything reaching beyond two callers should move
into its own module.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.json import JSON as RichJSON  # noqa: N811 — alias avoids clash with stdlib `json`

if TYPE_CHECKING:
    from collections.abc import Iterable

# A single shared Console instance avoids re-creating styles on every print.
console = Console()
err_console = Console(stderr=True)


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a `Z` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def print_json(payload: Any, *, pretty: bool = True) -> None:
    """Print JSON to stdout.

    When ``pretty`` is True we use Rich's syntax highlighter for the terminal.
    When piped to a file the user gets plain JSON.
    """
    if pretty and sys.stdout.isatty():
        console.print(RichJSON.from_data(payload))
    else:
        json.dump(payload, sys.stdout, indent=2, default=str, ensure_ascii=False)
        sys.stdout.write("\n")


def polite_sleep(seconds: float) -> None:
    """Synchronous polite delay — used by sync HTTP code paths."""
    if seconds > 0:
        import time

        time.sleep(seconds)


async def async_polite_sleep(seconds: float) -> None:
    """Async polite delay — used by Playwright / httpx async code paths."""
    if seconds > 0:
        await asyncio.sleep(seconds)


def dedupe_preserving_order(items: Iterable[str]) -> list[str]:
    """Return items with duplicates removed, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def clickable(url: str | None, display: str | None = None) -> str:
    """Wrap ``url`` in Rich link markup so it renders as a clickable hyperlink.

    Terminals that support OSC-8 escape sequences (iTerm2, recent macOS
    Terminal.app, Windows Terminal, VS Code's integrated terminal, Kitty,
    Alacritty, WezTerm, etc.) render the result as a hyperlink — ⌘-click
    (or Ctrl-click on Linux/Windows) opens it in the default browser.

    When the output is piped or redirected, Rich strips terminal control
    sequences automatically, so the result degrades to plain text — no
    ANSI gibberish in your log files.

    Returns ``display`` (or empty string) when ``url`` is falsy, so callers
    can pass through optional URLs without a guard.
    """
    if not url:
        return display or ""
    return f"[link={url}]{display or url}[/link]"
