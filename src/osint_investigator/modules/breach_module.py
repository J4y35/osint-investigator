"""``breach`` subcommand — check leak corpora for an email or domain.

Two sources are wired up:

1. **Have I Been Pwned (HIBP)** — authoritative breach index. Requires an API
   key (``HIBP_API_KEY`` in `.env`).
2. **DDoSecrets (ddosecrets.org)** — public leak catalogue. We fetch the
   front-page listing and grep for the query (skeleton; tighten the matcher
   once you've decided what counts as a hit).

Add new sources by writing another ``_lookup_*`` coroutine and registering it
in :data:`SOURCES`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Annotated, Any

import httpx
import typer
from rich.table import Table

from osint_investigator.config import get_settings
from osint_investigator.utils import (
    async_polite_sleep,
    console,
    err_console,
    print_json,
    utcnow_iso,
)

app = typer.Typer(
    name="breach",
    help="Check breach / leak datasets for an email or domain.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


@dataclass(slots=True)
class BreachHit:
    source: str
    name: str
    date: str | None = None
    description: str | None = None
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "name": self.name,
            "date": self.date,
            "description": self.description,
            "url": self.url,
            "extra": self.extra,
        }


# ── Have I Been Pwned ────────────────────────────────────────────────────────
async def _lookup_hibp(query: str, client: httpx.AsyncClient) -> list[BreachHit]:
    """Look up an email in HIBP's `breachedaccount` endpoint."""
    settings = get_settings()
    if not settings.hibp_api_key:
        err_console.print("[dim]hibp:[/] no HIBP_API_KEY set — skipping.")
        return []

    if "@" not in query:
        # HIBP's breachedaccount endpoint is email-only.
        return []

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}"
    headers = {
        "hibp-api-key": settings.hibp_api_key.get_secret_value(),
        "User-Agent": settings.user_agent,
    }
    try:
        await async_polite_sleep(settings.request_delay)
        resp = await client.get(url, headers=headers, params={"truncateResponse": "false"})
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[yellow]hibp request failed:[/] {exc}")
        return []

    if resp.status_code == 404:
        return []  # No breaches — HIBP signals this with 404.
    if resp.status_code != 200:
        err_console.print(f"[yellow]hibp unexpected status[/] {resp.status_code}: {resp.text[:200]}")
        return []

    out: list[BreachHit] = []
    for b in resp.json():
        out.append(
            BreachHit(
                source="HIBP",
                name=b.get("Name", "?"),
                date=b.get("BreachDate"),
                description=(b.get("Description") or "").strip(),
                url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
                extra={"data_classes": b.get("DataClasses", [])},
            )
        )
    return out


# ── DDoSecrets ───────────────────────────────────────────────────────────────
async def _lookup_ddosecrets(query: str, client: httpx.AsyncClient) -> list[BreachHit]:
    """Naive substring-match against the DDoSecrets release listing.

    The site is JS-light enough that an HTTP GET works; if/when it changes to a
    client-rendered SPA, swap to Playwright like the ``person`` module.
    """
    settings = get_settings()
    url = "https://ddosecrets.org/wiki/Special:AllPages"
    try:
        await async_polite_sleep(settings.request_delay)
        resp = await client.get(url, headers={"User-Agent": settings.user_agent})
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[yellow]ddosecrets request failed:[/] {exc}")
        return []

    if resp.status_code != 200:
        err_console.print(f"[yellow]ddosecrets status[/] {resp.status_code}")
        return []

    # Grep the AllPages index for the query (case-insensitive). Replace this
    # with a real BeautifulSoup parser once you've decided on a match heuristic.
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(resp.text, "lxml")
    out: list[BreachHit] = []
    q = query.lower()
    for a in soup.select("a[href^='/wiki/']"):
        title = (a.get_text() or "").strip()
        if q and q in title.lower():
            out.append(
                BreachHit(
                    source="DDoSecrets",
                    name=title,
                    url=f"https://ddosecrets.org{a.get('href')}",
                )
            )
    return out


SOURCES: dict[str, Any] = {
    "hibp": _lookup_hibp,
    "ddosecrets": _lookup_ddosecrets,
}


async def _run_all(query: str) -> list[BreachHit]:
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as client:
        tasks = [src(query, client) for src in SOURCES.values()]
        nested = await asyncio.gather(*tasks, return_exceptions=False)
    return [hit for batch in nested for hit in batch]


def _render_table(query: str, hits: list[BreachHit]) -> Table:
    table = Table(title=f"Breach hits for {query}", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Date")
    table.add_column("Description", overflow="fold")
    table.add_column("URL", overflow="fold", style="dim")
    for h in hits:
        desc = (h.description or "").replace("\n", " ")
        table.add_row(h.source, h.name, h.date or "", desc[:160], h.url or "")
    return table


@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    query: Annotated[
        str,
        typer.Option(
            "--query", "-q",
            help="Email or domain to search for in breach corpora.",
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of a table.")] = False,
) -> None:
    """Check breach datasets (HIBP, DDoSecrets) for an email or domain."""
    if ctx.invoked_subcommand is not None:
        return

    hits = asyncio.run(_run_all(query))

    if json_output:
        print_json(
            {
                "query": query,
                "checked_at": utcnow_iso(),
                "total_hits": len(hits),
                "results": [h.to_dict() for h in hits],
            }
        )
        return

    if not hits:
        console.print(f"[green]No breach hits for[/] [bold]{query}[/].")
        return
    console.print(_render_table(query, hits))
    console.print(f"\n[bold]Summary:[/] {len(hits)} hit(s) across {len(SOURCES)} source(s).")
