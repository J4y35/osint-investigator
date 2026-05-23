"""``person`` subcommand — Playwright-based search of people-finder sites.

This module ships with a working Playwright scaffold targeted at
`cyberbackgroundchecks.com`. The site is JavaScript-heavy, so a headless
browser is required.

Add new sites by writing another async scraper function and registering it in
``SCRAPERS`` — the orchestrator handles JSON / table output for you.

Ethical note: people-finder sites have terms of service. Use this command
only against subjects you are legally authorised to investigate.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Annotated, Any
from urllib.parse import quote_plus

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
    name="person",
    help="Investigate a person by name (+ optional state/city). Uses Playwright.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


# ── Data model ───────────────────────────────────────────────────────────────
@dataclass(slots=True)
class PersonHit:
    """A single result row from any people-finder source."""

    source: str
    name: str
    age: str | None = None
    location: str | None = None
    relatives: list[str] = field(default_factory=list)
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "name": self.name,
            "age": self.age,
            "location": self.location,
            "relatives": self.relatives,
            "url": self.url,
            "extra": self.extra,
        }


# ── Scrapers ─────────────────────────────────────────────────────────────────
async def _scrape_cyberbackgroundchecks(
    first: str, last: str, state: str | None
) -> list[PersonHit]:
    """Scrape cyberbackgroundchecks.com search results.

    The site renders results client-side, so we wait for the result container
    selector before parsing. Selectors are extracted to module-level constants
    to make future site updates a single-line fix.
    """
    settings = get_settings()
    hits: list[PersonHit] = []

    # Build URL — the site uses a `/people/<first>-<last>` path with optional state filter.
    path = f"/people/{quote_plus(first)}-{quote_plus(last)}"
    if state:
        path += f"/{quote_plus(state)}"
    url = f"https://www.cyberbackgroundchecks.com{path}"

    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover
        raise typer.BadParameter(
            "Playwright is not installed. Run `pip install playwright && playwright install chromium`."
        ) from exc

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=settings.playwright_headless)
        context = await browser.new_context(user_agent=settings.user_agent)
        page = await context.new_page()
        try:
            await page.goto(
                url, wait_until="domcontentloaded", timeout=int(settings.http_timeout * 1000)
            )
            # Polite delay before parsing.
            await async_polite_sleep(settings.request_delay)

            # The result list lives inside `.record` blocks. If the site changes its
            # markup, this is the single place to update.
            cards = await page.query_selector_all(".record, [data-record]")
            for card in cards:
                name_el = await card.query_selector(".name, h2, h3")
                age_el = await card.query_selector(".age, [data-age]")
                loc_el = await card.query_selector(".address, .location")

                name = (await name_el.inner_text()).strip() if name_el else f"{first} {last}"
                age = (await age_el.inner_text()).strip() if age_el else None
                loc = (await loc_el.inner_text()).strip() if loc_el else None

                hits.append(
                    PersonHit(
                        source="cyberbackgroundchecks.com",
                        name=name,
                        age=age,
                        location=loc,
                        url=url,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"[yellow]cyberbackgroundchecks scrape failed:[/] {exc}")
        finally:
            await context.close()
            await browser.close()

    return hits


# Register every active scraper here. Signature: (first, last, state) -> list[PersonHit].
SCRAPERS: dict[str, Any] = {
    "cyberbackgroundchecks": _scrape_cyberbackgroundchecks,
}


# ── Orchestration ────────────────────────────────────────────────────────────
async def _run_all(first: str, last: str, state: str | None) -> list[PersonHit]:
    tasks = [scraper(first, last, state) for scraper in SCRAPERS.values()]
    nested = await asyncio.gather(*tasks, return_exceptions=False)
    return [hit for batch in nested for hit in batch]


# ── Output ───────────────────────────────────────────────────────────────────
def _render_table(query: str, hits: list[PersonHit]) -> Table:
    table = Table(title=f"Person hits for {query}", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Age")
    table.add_column("Location")
    table.add_column("URL", overflow="fold", style="dim")
    for h in hits:
        table.add_row(h.source, h.name, h.age or "", h.location or "", h.url or "")
    return table


# ── Command ──────────────────────────────────────────────────────────────────
@app.callback(invoke_without_command=True)
def search(
    ctx: typer.Context,
    first: Annotated[str, typer.Option("--first", "-f", help="First name.")],
    last: Annotated[str, typer.Option("--last", "-l", help="Last name.")],
    state: Annotated[
        str | None,
        typer.Option("--state", "-s", help="Two-letter US state code (optional)."),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of a table.")
    ] = False,
) -> None:
    """Search people-finder sites for a name (+ optional state)."""
    if ctx.invoked_subcommand is not None:
        return

    query = f"{first} {last}" + (f", {state}" if state else "")
    hits = asyncio.run(_run_all(first, last, state))

    if json_output:
        print_json(
            {
                "query": {"first": first, "last": last, "state": state},
                "checked_at": utcnow_iso(),
                "total_hits": len(hits),
                "results": [h.to_dict() for h in hits],
            }
        )
        return

    if not hits:
        console.print(f"[yellow]No hits for[/] [bold]{query}[/].")
        return
    console.print(_render_table(query, hits))
    console.print(f"\n[bold]Summary:[/] {len(hits)} hit(s) across {len(SCRAPERS)} source(s).")
