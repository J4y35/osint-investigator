"""``breach`` subcommand — check leak corpora for an email or domain.

Two sources are wired up:

1. **Have I Been Pwned (HIBP)** — authoritative breach index. Requires an
   API key (``HIBP_API_KEY`` in `.env`); without one the source reports
   ``no_auth`` rather than silently returning nothing.
2. **DDoSecrets (ddosecrets.org)** — public leak catalogue. We fetch the
   recent-articles page and substring-match the query against article
   titles. Best for dataset names ("blueleaks", "epstein"), not
   individual emails.

Like ``person`` and ``domain``, each source returns a :class:`BreachResult`
with explicit status (``ok`` / ``empty`` / ``rate_limited`` / ``no_auth``
/ ``error``) so the CLI surfaces *why* a source returned nothing.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Literal

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
    name="breach",
    help="Check breach / leak datasets for an email or domain.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


# ── Data model ───────────────────────────────────────────────────────────────

BreachStatus = Literal["ok", "empty", "rate_limited", "no_auth", "error"]


@dataclass(slots=True)
class BreachHit:
    source: str
    name: str
    date: str | None = None
    description: str | None = None
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class BreachResult:
    """Outcome of querying one breach source."""

    source: str
    status: BreachStatus
    hits: list[BreachHit] = field(default_factory=list)
    message: str | None = None


# ── Pure parsers (tested with fixtures) ──────────────────────────────────────


def parse_hibp_response(payload: list[dict[str, Any]]) -> list[BreachHit]:
    """Map HIBP's ``breachedaccount`` JSON response to :class:`BreachHit`s.

    The endpoint returns a list of breach objects (with ``truncateResponse=false``);
    we keep name, breach date, description, and data classes.
    """
    out: list[BreachHit] = []
    for b in payload or []:
        name = b.get("Name") or "?"
        out.append(
            BreachHit(
                source="HIBP",
                name=name,
                date=b.get("BreachDate"),
                description=(b.get("Description") or "").strip() or None,
                url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                extra={"data_classes": list(b.get("DataClasses") or [])},
            )
        )
    return out


def parse_ddosecrets_html(html: str, query: str) -> list[BreachHit]:
    """Substring-match the DDoSecrets recent-articles page for ``query``.

    DDoSecrets' current site lists articles at ``/article/<slug>``. Each
    article appears twice in the markup (title link + "Read more" link);
    we dedupe by href and skip the "Read more" anchor.
    """
    from bs4 import BeautifulSoup

    q = (query or "").lower().strip()
    if not q:
        return []

    soup = BeautifulSoup(html, "lxml")
    out: list[BreachHit] = []
    seen_hrefs: set[str] = set()

    for a in soup.select("a[href^='/article/']"):
        href = a.get("href") or ""
        if href in seen_hrefs:
            continue
        seen_hrefs.add(href)
        title = (a.get_text() or "").strip()
        if not title or title.lower() == "read more":
            continue
        if q in title.lower():
            out.append(
                BreachHit(
                    source="DDoSecrets",
                    name=title,
                    url=f"https://ddosecrets.org{href}",
                )
            )
    return out


# ── Sources (network code — thin wrappers over the parsers) ──────────────────


async def _lookup_hibp(query: str, client: httpx.AsyncClient) -> BreachResult:
    """Query HIBP's `breachedaccount` endpoint for an email."""
    settings = get_settings()
    if not settings.hibp_api_key:
        return BreachResult("hibp", "no_auth", message="HIBP_API_KEY not set")
    if "@" not in query:
        # HIBP's breachedaccount endpoint is email-only — be explicit about why.
        return BreachResult("hibp", "empty", message="HIBP breach search requires an email address")

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}"
    headers = {
        "hibp-api-key": settings.hibp_api_key.get_secret_value(),
        "User-Agent": settings.user_agent,
    }
    try:
        await async_polite_sleep(settings.request_delay)
        resp = await retrying_get(
            client, url, headers=headers, params={"truncateResponse": "false"}
        )
    except Exception as exc:  # noqa: BLE001
        return BreachResult("hibp", "error", message=f"{type(exc).__name__}: {exc}")

    if resp.status_code == 404:
        # HIBP uses 404 to signal "no breaches" — that's a clean empty result.
        return BreachResult("hibp", "empty", message="no breaches found for this email")
    if resp.status_code == 401:
        return BreachResult("hibp", "no_auth", message="HIBP rejected the API key (401)")
    if resp.status_code == 429:
        return BreachResult(
            "hibp",
            "rate_limited",
            message="HIBP rate limit hit after retries — wait and try again",
        )
    if resp.status_code != 200:
        return BreachResult(
            "hibp",
            "error",
            message=f"HTTP {resp.status_code} from HIBP: {resp.text[:160]}",
        )

    hits = parse_hibp_response(resp.json())
    if not hits:
        return BreachResult("hibp", "empty", message="response contained no breaches")
    return BreachResult("hibp", "ok", hits=hits, message=f"{len(hits)} breach(es) found")


_DDOSECRETS_INDEX = "https://ddosecrets.org/all_articles/recent"


async def _lookup_ddosecrets(query: str, client: httpx.AsyncClient) -> BreachResult:
    """Substring-match the DDoSecrets recent-articles catalogue for ``query``."""
    settings = get_settings()
    try:
        await async_polite_sleep(settings.request_delay)
        resp = await retrying_get(
            client, _DDOSECRETS_INDEX, headers={"User-Agent": settings.user_agent}
        )
    except Exception as exc:  # noqa: BLE001
        return BreachResult("ddosecrets", "error", message=f"{type(exc).__name__}: {exc}")

    if resp.status_code == 429:
        return BreachResult(
            "ddosecrets", "rate_limited", message="DDoSecrets rate limit after retries"
        )
    if resp.status_code != 200:
        return BreachResult(
            "ddosecrets", "error", message=f"HTTP {resp.status_code} from ddosecrets.org"
        )

    hits = parse_ddosecrets_html(resp.text, query)
    if not hits:
        return BreachResult("ddosecrets", "empty", message="no recent articles matched the query")
    return BreachResult(
        "ddosecrets",
        "ok",
        hits=hits,
        message=f"{len(hits)} matching article(s)",
    )


SOURCES: dict[str, Any] = {
    "hibp": _lookup_hibp,
    "ddosecrets": _lookup_ddosecrets,
}


# ── Orchestration + rendering ────────────────────────────────────────────────


async def _run_all(query: str) -> list[BreachResult]:
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as client:
        return await asyncio.gather(*(src(query, client) for src in SOURCES.values()))


_STATUS_STYLE: dict[BreachStatus, str] = {
    "ok": "[green]ok[/]",
    "empty": "[yellow]empty[/]",
    "rate_limited": "[red]rate-limited[/]",
    "no_auth": "[red]no-auth[/]",
    "error": "[red]error[/]",
}


def _render_status_panel(results: list[BreachResult]) -> Table:
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


def _render_hits_table(query: str, hits: list[BreachHit]) -> Table:
    table = Table(title=f"Breach hits for {query}", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Date")
    table.add_column("Description", overflow="fold")
    table.add_column("URL", overflow="fold", style="dim")
    for h in hits:
        desc = (h.description or "").replace("\n", " ")
        table.add_row(h.source, h.name, h.date or "", desc[:160], clickable(h.url))
    return table


# ── Command ──────────────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    query: Annotated[
        str,
        typer.Option(
            "--query",
            "-q",
            help="Email or domain to search for in breach corpora.",
        ),
    ],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of a table.")
    ] = False,
) -> None:
    """Check breach datasets (HIBP, DDoSecrets) for an email or domain."""
    if ctx.invoked_subcommand is not None:
        return

    results = asyncio.run(_run_all(query))
    all_hits = [h for r in results for h in r.hits]

    if json_output:
        print_json(
            {
                "query": query,
                "checked_at": utcnow_iso(),
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
        console.print(f"\n[green]No breach hits for[/] [bold]{query}[/].")
        # Surface auth / rate-limit issues on stderr so users notice.
        for r in results:
            if r.status in ("rate_limited", "no_auth"):
                err_console.print(f"[red]{r.source}[/]: {r.message}")
        return
    console.print(_render_hits_table(query, all_hits))
    console.print(f"\n[bold]Summary:[/] {len(all_hits)} hit(s) across {len(SOURCES)} source(s).")
