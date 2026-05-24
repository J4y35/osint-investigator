"""``person`` subcommand — multi-source people-finder.

The command queries every registered source and reports per-source status
so you can tell "Cloudflare blocked us" apart from "no matching records".

Sources (current):

- **CourtListener** (`courtlistener`) — federal court records via the free
  v4 REST API. Returns dockets where the subject's name appears as a party.
  No auth required for basic search.
- **cyberbackgroundchecks** (`cyberbackgroundchecks`) — JavaScript-heavy
  background-check aggregator. Frequently blocked by Cloudflare's bot
  challenge; in that case the source reports ``blocked`` with a clear
  message rather than silently returning zero hits.

Ethical note: people-finder sites have terms of service and public-record
sources should be used only for purposes the relevant jurisdictions
permit. Use this command responsibly.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Literal
from urllib.parse import quote_plus

import httpx
import typer
from rich.table import Table

from osint_investigator.config import get_settings
from osint_investigator.retry import retrying_get
from osint_investigator.utils import (
    async_polite_sleep,
    clickable,
    console,
    err_console,
    print_json,
    utcnow_iso,
)

app = typer.Typer(
    name="person",
    help="Investigate a person by name (+ optional state). Multi-source.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


# ── Data model ───────────────────────────────────────────────────────────────
SourceStatus = Literal["ok", "blocked", "error", "empty"]


@dataclass(slots=True)
class PersonHit:
    """A single result row from any source. ``extra`` carries source-specific keys."""

    source: str
    name: str
    age: str | None = None
    location: str | None = None
    relatives: list[str] = field(default_factory=list)
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SourceResult:
    """Outcome of querying a single source.

    ``status`` lets the CLI distinguish "no matches" from "we couldn't even
    talk to the site". ``message`` is a one-line operator-facing diagnostic.
    """

    source: str
    status: SourceStatus
    hits: list[PersonHit] = field(default_factory=list)
    message: str | None = None


# ── Parsers (pure functions — tested with fixtures, no network) ──────────────


# Markers that uniquely identify a Cloudflare interstitial. Both must be
# checked because the literal text "Just a moment..." sometimes appears
# legitimately, and the body class is sometimes present without the title.
_CLOUDFLARE_MARKERS = (
    "Just a moment...",
    "challenge-platform",
    "cf-mitigated",
    "__cf_chl",
    "Performing security verification",
)


def is_cloudflare_interstitial(html: str, title: str = "") -> bool:
    """Heuristic: does this look like a Cloudflare bot-challenge page?

    Two-of-N matching keeps us from misfiring on pages that just happen to
    contain one of the markers in unrelated content.
    """
    haystack = f"{title}\n{html}"
    return sum(1 for m in _CLOUDFLARE_MARKERS if m in haystack) >= 2


def parse_cyberbackgroundchecks_html(html: str, first: str, last: str) -> list[PersonHit]:
    """Parse a cyberbackgroundchecks search results page.

    The site renders results as a flat list of cards inside a results
    container. Selectors are best-effort against the public DOM as of the
    last successful capture; if the site re-skins, replace the fixture and
    update the constants below.

    Returns an empty list for "no results" pages or unrecognised markup —
    callers should rely on :class:`SourceResult.status` to disambiguate.
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    cards = soup.select(".record, [data-record], article.result, .person-result")
    hits: list[PersonHit] = []
    for card in cards:
        name_el = card.select_one(".name, h2, h3, .full-name")
        age_el = card.select_one(".age, [data-age]")
        loc_el = card.select_one(".address, .location, .city-state")
        name = name_el.get_text(strip=True) if name_el else f"{first} {last}"
        hits.append(
            PersonHit(
                source="cyberbackgroundchecks.com",
                name=name,
                age=age_el.get_text(strip=True) if age_el else None,
                location=loc_el.get_text(strip=True) if loc_el else None,
            )
        )
    return hits


def parse_courtlistener_response(payload: dict[str, Any]) -> list[PersonHit]:
    """Map a CourtListener ``search`` API payload into :class:`PersonHit`s.

    Designed against ``type=r`` (RECAP) responses, which list court
    dockets. Fields used: ``caseName``, ``court``, ``dateFiled``,
    ``docketNumber``, ``absolute_url``. Each docket becomes one hit.
    """
    hits: list[PersonHit] = []
    base = "https://www.courtlistener.com"
    for entry in payload.get("results") or []:
        case = entry.get("caseName") or entry.get("caseNameShort") or "unknown case"
        court = entry.get("court") or entry.get("court_id") or ""
        date_filed = entry.get("dateFiled") or ""
        docket = entry.get("docketNumber") or ""
        # RECAP (`type=r`) responses use `docket_absolute_url`; the people
        # search (`type=p`) uses `absolute_url`. Accept either so the parser
        # stays useful if we wire up the second search type later.
        rel = entry.get("docket_absolute_url") or entry.get("absolute_url") or ""
        full_url = f"{base}{rel}" if rel.startswith("/") else (rel or None)
        extra: dict[str, Any] = {}
        if date_filed:
            extra["date_filed"] = date_filed
        if docket:
            extra["docket_number"] = docket
        # Surface the assigned judge when present — useful for OSINT.
        if entry.get("assignedTo"):
            extra["assigned_to"] = entry["assignedTo"]
        hits.append(
            PersonHit(
                source="courtlistener.com",
                name=case,
                location=court or None,
                url=full_url,
                extra=extra,
            )
        )
    return hits


# ── Sources (network code — thin wrappers over the parsers) ──────────────────


async def _search_courtlistener(first: str, last: str, state: str | None) -> SourceResult:
    """Query CourtListener's v4 RECAP search and return mapped hits.

    State, when provided, is folded into the query string as a free-text
    hint — CourtListener doesn't index party-of-record locations directly.
    """
    settings = get_settings()
    query = f"{first} {last}"
    if state:
        query = f"{query} {state}"
    url = "https://www.courtlistener.com/api/rest/v4/search/"
    params = {"type": "r", "q": query, "page_size": "20"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code != 200:
            return SourceResult(
                "courtlistener",
                "error",
                message=f"HTTP {resp.status_code} from CourtListener",
            )
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SourceResult("courtlistener", "error", message=f"{type(exc).__name__}: {exc}")

    hits = parse_courtlistener_response(payload)
    if not hits:
        return SourceResult("courtlistener", "empty", message="no matching dockets")
    total = payload.get("count")
    msg = f"showing {len(hits)} of {total} dockets" if total else f"{len(hits)} hits"
    return SourceResult("courtlistener", "ok", hits=hits, message=msg)


async def _scrape_cyberbackgroundchecks(first: str, last: str, state: str | None) -> SourceResult:
    """Playwright scrape with explicit Cloudflare detection.

    cyberbackgroundchecks is fronted by Cloudflare Turnstile. When the gate
    triggers we surface a ``blocked`` status — the operator can decide
    whether to try again from a residential IP, supply a proxy, or run a
    real browser session manually. We do *not* attempt to bypass the
    challenge.
    """
    settings = get_settings()
    path = f"/people/{quote_plus(first)}-{quote_plus(last)}"
    if state:
        path += f"/{quote_plus(state)}"
    page_url = f"https://www.cyberbackgroundchecks.com{path}"

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return SourceResult(
            "cyberbackgroundchecks",
            "error",
            message="playwright not installed (run `playwright install chromium`)",
        )

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=settings.playwright_headless)
        context = await browser.new_context(user_agent=settings.user_agent)
        page = await context.new_page()
        try:
            resp = await page.goto(
                page_url, wait_until="domcontentloaded", timeout=int(settings.http_timeout * 1000)
            )
            status = resp.status if resp else None
            await async_polite_sleep(settings.request_delay)
            html = await page.content()
            title = await page.title()

            if is_cloudflare_interstitial(html, title) or status == 403:
                return SourceResult(
                    "cyberbackgroundchecks",
                    "blocked",
                    message=(
                        "Cloudflare bot challenge — site requires a real browser "
                        "session or residential proxy"
                    ),
                )
            hits = parse_cyberbackgroundchecks_html(html, first, last)
            if not hits:
                return SourceResult(
                    "cyberbackgroundchecks", "empty", message="no result cards parsed"
                )
            # Backfill the canonical URL on each hit.
            for h in hits:
                h.url = page_url
            return SourceResult(
                "cyberbackgroundchecks", "ok", hits=hits, message=f"{len(hits)} cards parsed"
            )
        except Exception as exc:  # noqa: BLE001
            return SourceResult(
                "cyberbackgroundchecks",
                "error",
                message=f"{type(exc).__name__}: {exc}",
            )
        finally:
            await context.close()
            await browser.close()


# Registry. Adding a source means adding one async callable here.
SOURCES: dict[str, Any] = {
    "courtlistener": _search_courtlistener,
    "cyberbackgroundchecks": _scrape_cyberbackgroundchecks,
}


# ── Orchestration ────────────────────────────────────────────────────────────


async def _run_all(
    first: str, last: str, state: str | None, sources: list[str]
) -> list[SourceResult]:
    coros = [SOURCES[s](first, last, state) for s in sources]
    results: list[SourceResult] = await asyncio.gather(*coros)
    return results


# ── Output ───────────────────────────────────────────────────────────────────


_STATUS_STYLE: dict[SourceStatus, str] = {
    "ok": "[green]ok[/]",
    "empty": "[yellow]empty[/]",
    "blocked": "[red]blocked[/]",
    "error": "[red]error[/]",
}


def _render_status_panel(results: list[SourceResult]) -> Table:
    table = Table(title="Source status", show_lines=False)
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", style="dim", overflow="fold")
    table.add_column("Hits", justify="right")
    for r in results:
        table.add_row(
            r.source,
            _STATUS_STYLE.get(r.status, r.status),
            r.message or "",
            str(len(r.hits)),
        )
    return table


def _render_hits_table(query: str, hits: list[PersonHit]) -> Table:
    table = Table(title=f"Hits for {query}", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Name / Case", style="bold")
    table.add_column("Location / Court")
    table.add_column("Detail", style="dim")
    table.add_column("URL", overflow="fold", style="dim")
    for h in hits:
        detail_parts = []
        if h.age:
            detail_parts.append(f"age {h.age}")
        for k, v in (h.extra or {}).items():
            detail_parts.append(f"{k}: {v}")
        table.add_row(
            h.source,
            h.name,
            h.location or "",
            ", ".join(detail_parts),
            clickable(h.url),
        )
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
    sources: Annotated[
        list[str] | None,
        typer.Option(
            "--source",
            help=(
                "Sources to query. Repeat to pick multiple. "
                f"Available: {', '.join(SOURCES)}. Default: courtlistener."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of tables.")
    ] = False,
) -> None:
    """Search public-record and people-finder sources for a name."""
    if ctx.invoked_subcommand is not None:
        return

    chosen = sources or ["courtlistener"]
    unknown = [s for s in chosen if s not in SOURCES]
    if unknown:
        raise typer.BadParameter(
            f"Unknown source(s): {', '.join(unknown)}. Available: {', '.join(SOURCES)}.",
            param_hint="--source",
        )

    query = f"{first} {last}" + (f", {state}" if state else "")
    results = asyncio.run(_run_all(first, last, state, chosen))
    all_hits = [h for r in results for h in r.hits]

    if json_output:
        print_json(
            {
                "query": {"first": first, "last": last, "state": state},
                "checked_at": utcnow_iso(),
                "sources": chosen,
                "source_status": [
                    {
                        "source": r.source,
                        "status": r.status,
                        "message": r.message,
                        "hit_count": len(r.hits),
                    }
                    for r in results
                ],
                "total_hits": len(all_hits),
                "results": [asdict(h) for h in all_hits],
            }
        )
        return

    console.print(_render_status_panel(results))
    if not all_hits:
        console.print(f"\n[yellow]No hits for[/] [bold]{query}[/].")
        # Surface blocked-source advice on the error stream so it's not
        # mixed into the (empty) data stream.
        for r in results:
            if r.status == "blocked":
                err_console.print(f"[red]{r.source}[/]: {r.message}")
        return
    console.print(_render_hits_table(query, all_hits))
    console.print(f"\n[bold]Summary:[/] {len(all_hits)} hit(s) across {len(chosen)} source(s).")
