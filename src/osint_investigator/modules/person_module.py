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
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote_plus

import httpx
import typer
from rich.table import Table

from osint_investigator.config import get_settings
from osint_investigator.retry import retrying_get
from osint_investigator.utils import (
    append_jsonl,
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


def parse_opencorporates_response(payload: dict[str, Any]) -> list[PersonHit]:
    """Map OpenCorporates' ``officers/search`` response into :class:`PersonHit`s.

    Each result represents a company officership: who the person is, which
    company, which role (director/secretary/etc), and the source jurisdiction.

    Schema (v0.4 as documented):
        results.officers[].officer.{name, position, company.{name, jurisdiction_code,
            opencorporates_url}, start_date, end_date, opencorporates_url}
    """
    hits: list[PersonHit] = []
    results = (payload.get("results") or {}).get("officers") or []
    for wrapper in results:
        officer = wrapper.get("officer") or {}
        name = officer.get("name") or "unknown officer"
        position = officer.get("position") or ""
        company = officer.get("company") or {}
        company_name = company.get("name") or ""
        jurisdiction = company.get("jurisdiction_code") or ""
        url = officer.get("opencorporates_url") or company.get("opencorporates_url")
        extra: dict[str, Any] = {}
        if position:
            extra["position"] = position
        if company_name:
            extra["company"] = company_name
        if jurisdiction:
            extra["jurisdiction"] = jurisdiction
        if officer.get("start_date"):
            extra["start_date"] = officer["start_date"]
        if officer.get("end_date"):
            extra["end_date"] = officer["end_date"]
        hits.append(
            PersonHit(
                source="opencorporates.com",
                name=name,
                location=jurisdiction or None,
                url=url,
                extra=extra,
            )
        )
    return hits


def parse_fec_response(payload: dict[str, Any]) -> list[PersonHit]:
    """Map FEC ``schedules/schedule_a`` (individual contributions) into hits.

    Each result is a single political donation. The contributor's name,
    self-reported employer/occupation, donation amount, recipient committee,
    and contribution date are all surfaced.

    Schema (api.open.fec.gov v1):
        results[].{contributor_name, contributor_city, contributor_state,
            contributor_employer, contributor_occupation, contribution_receipt_amount,
            contribution_receipt_date, committee.{name}, contributor_aggregate_ytd,
            pdf_url}
    """
    hits: list[PersonHit] = []
    for entry in payload.get("results") or []:
        name = entry.get("contributor_name") or "unknown contributor"
        city = entry.get("contributor_city") or ""
        state = entry.get("contributor_state") or ""
        location = ", ".join([p for p in (city, state) if p]) or None
        committee = (entry.get("committee") or {}).get("name") or entry.get("committee_name") or ""
        amount = entry.get("contribution_receipt_amount")
        extra: dict[str, Any] = {}
        if entry.get("contribution_receipt_date"):
            extra["date"] = entry["contribution_receipt_date"]
        if amount is not None:
            extra["amount_usd"] = amount
        if committee:
            extra["committee"] = committee
        if entry.get("contributor_employer"):
            extra["employer"] = entry["contributor_employer"]
        if entry.get("contributor_occupation"):
            extra["occupation"] = entry["contributor_occupation"]
        hits.append(
            PersonHit(
                source="fec.gov",
                name=name,
                location=location,
                url=entry.get("pdf_url") or None,
                extra=extra,
            )
        )
    return hits


def parse_edgar_response(payload: dict[str, Any]) -> list[PersonHit]:
    """Map SEC EDGAR full-text-search results into :class:`PersonHit`s.

    Each hit is one filing where the search term appeared. We expose the
    filing form, date, CIK, and the display_names (which usually carry the
    company name plus its ticker).

    Schema (efts.sec.gov/LATEST/search-index):
        hits.hits[]._source.{form, file_date, adsh, ciks[], display_names[],
            file_description, biz_locations[]}
    """
    hits: list[PersonHit] = []
    for h in (payload.get("hits") or {}).get("hits") or []:
        src = h.get("_source") or {}
        names = src.get("display_names") or []
        display = names[0] if names else "unknown filer"
        cik = (src.get("ciks") or [""])[0]
        adsh = src.get("adsh") or ""
        biz_locs = src.get("biz_locations") or []
        location = biz_locs[0] if biz_locs else None
        # EDGAR filing index URL pattern; CIK without leading zeros, adsh
        # with dashes stripped for the path, original adsh for the filename.
        url: str | None = None
        if cik and adsh:
            adsh_no_dash = adsh.replace("-", "")
            try:
                cik_int = int(cik)
            except ValueError:
                cik_int = 0
            if cik_int:
                url = (
                    f"https://www.sec.gov/Archives/edgar/data/"
                    f"{cik_int}/{adsh_no_dash}/{adsh}-index.htm"
                )
        extra: dict[str, Any] = {}
        if src.get("form"):
            extra["form"] = src["form"]
        if src.get("file_date"):
            extra["file_date"] = src["file_date"]
        if src.get("file_description"):
            extra["description"] = src["file_description"]
        if cik:
            extra["cik"] = cik
        hits.append(
            PersonHit(
                source="sec.gov/EDGAR",
                name=display,
                location=location,
                url=url,
                extra=extra,
            )
        )
    return hits


def parse_trade_gov_csl_response(payload: dict[str, Any]) -> list[PersonHit]:
    """Map Trade.gov's consolidated screening list response into hits.

    The CSL aggregates the OFAC SDN list, the BIS Entity List, the State
    Department's Debarred List, and other US-government sanctions /
    restricted-party lists. Any hit here is significant for due-diligence
    work — the person is on a list that restricts US persons from doing
    business with them.

    Schema (search.api.trade.gov/v1/consolidated_screening_list/search):
        results[].{name, source, source_list_url, type, addresses[],
            programs[], remarks, citizenships, dates_of_birth, ids[]}
    """
    hits: list[PersonHit] = []
    for entry in payload.get("results") or []:
        name = entry.get("name") or "unnamed party"
        source_name = entry.get("source") or entry.get("source_list_url") or "Trade.gov CSL"
        addresses = entry.get("addresses") or []
        location: str | None = None
        if addresses:
            addr = addresses[0]
            parts = [addr.get("city"), addr.get("country")]
            location = ", ".join(p for p in parts if p) or None
        extra: dict[str, Any] = {}
        if entry.get("type"):
            extra["entity_type"] = entry["type"]
        if entry.get("programs"):
            extra["programs"] = entry["programs"]
        if entry.get("remarks"):
            extra["remarks"] = entry["remarks"]
        if entry.get("citizenships"):
            extra["citizenships"] = entry["citizenships"]
        if entry.get("source"):
            extra["list"] = entry["source"]
        hits.append(
            PersonHit(
                source=f"trade.gov ({source_name})",
                name=name,
                location=location,
                url=entry.get("source_list_url") or None,
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


async def _search_opencorporates(first: str, last: str, state: str | None) -> SourceResult:
    """Query OpenCorporates' officer search.

    Requires ``OPENCORPORATES_API_KEY`` (free tier as of 2023; register at
    https://opencorporates.com/api_accounts/new). ``state`` becomes part of
    the free-text query but isn't used as a jurisdiction filter.
    """
    settings = get_settings()
    if not settings.opencorporates_api_key:
        return SourceResult("opencorporates", "error", message="OPENCORPORATES_API_KEY not set")
    query = f"{first} {last}"
    if state:
        query = f"{query} {state}"
    url = "https://api.opencorporates.com/v0.4/officers/search"
    params = {
        "q": query,
        "format": "json",
        "api_token": settings.opencorporates_api_key.get_secret_value(),
        "per_page": "20",
    }
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code in (401, 403):
            return SourceResult(
                "opencorporates", "error", message="OpenCorporates rejected the API key"
            )
        if resp.status_code != 200:
            return SourceResult(
                "opencorporates", "error", message=f"HTTP {resp.status_code} from OpenCorporates"
            )
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SourceResult("opencorporates", "error", message=f"{type(exc).__name__}: {exc}")

    hits = parse_opencorporates_response(payload)
    if not hits:
        return SourceResult("opencorporates", "empty", message="no matching officerships")
    total = (payload.get("results") or {}).get("total_count")
    msg = f"showing {len(hits)} of {total}" if total else f"{len(hits)} hits"
    return SourceResult("opencorporates", "ok", hits=hits, message=msg)


async def _search_fec(first: str, last: str, state: str | None) -> SourceResult:
    """Query FEC's individual-contribution endpoint.

    Requires ``FEC_API_KEY`` (free, from api.data.gov). When ``state`` is
    provided it's passed as ``contributor_state`` to narrow the result set.
    """
    settings = get_settings()
    if not settings.fec_api_key:
        return SourceResult("fec", "error", message="FEC_API_KEY not set")

    url = "https://api.open.fec.gov/v1/schedules/schedule_a/"
    params: dict[str, str] = {
        "contributor_name": f"{first} {last}",
        "api_key": settings.fec_api_key.get_secret_value(),
        "per_page": "20",
        "sort": "-contribution_receipt_date",
    }
    if state:
        params["contributor_state"] = state.upper()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code in (401, 403):
            return SourceResult("fec", "error", message="FEC rejected the API key (401/403)")
        if resp.status_code != 200:
            return SourceResult("fec", "error", message=f"HTTP {resp.status_code} from FEC")
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SourceResult("fec", "error", message=f"{type(exc).__name__}: {exc}")

    hits = parse_fec_response(payload)
    if not hits:
        return SourceResult("fec", "empty", message="no matching individual contributions")
    total = (payload.get("pagination") or {}).get("count")
    msg = f"showing {len(hits)} of {total}" if total else f"{len(hits)} hits"
    return SourceResult("fec", "ok", hits=hits, message=msg)


async def _search_edgar(first: str, last: str, state: str | None) -> SourceResult:
    """Query SEC EDGAR's full-text search.

    No auth required, but SEC's WAF blocks User-Agents that include
    parenthesized URLs or the literal ``github.com`` — patterns common
    to scrapers. We override the global ``OSINT_USER_AGENT`` here with
    a plain product identifier that EDGAR accepts.

    ``state`` is ignored — EDGAR's full-text search doesn't take a
    person-state filter, and pre-filtering on company state usually
    isn't what an investigator wants.
    """
    from osint_investigator import __version__

    settings = get_settings()
    url = "https://efts.sec.gov/LATEST/search-index"
    # Quoted phrase forces exact-name match — much higher signal than the
    # default "any of these words" behaviour.
    params = {"q": f'"{first} {last}"'}
    edgar_user_agent = f"osint-investigator-cli/{__version__}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": edgar_user_agent, "Accept": "application/json"},
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code != 200:
            return SourceResult("edgar", "error", message=f"HTTP {resp.status_code} from EDGAR")
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SourceResult("edgar", "error", message=f"{type(exc).__name__}: {exc}")

    hits = parse_edgar_response(payload)
    if not hits:
        return SourceResult("edgar", "empty", message="no SEC filings matched")
    total = (payload.get("hits") or {}).get("total", {}).get("value")
    msg = f"showing {len(hits)} of {total} filings" if total else f"{len(hits)} hits"
    return SourceResult("edgar", "ok", hits=hits, message=msg)


async def _search_trade_gov_csl(first: str, last: str, state: str | None) -> SourceResult:
    """Query Trade.gov's consolidated screening list.

    Aggregates OFAC SDN + BIS Entity List + State Dept lists. Requires
    ``TRADE_GOV_API_KEY``. ``state`` is ignored — the CSL filters on country,
    not US state.
    """
    settings = get_settings()
    if not settings.trade_gov_api_key:
        return SourceResult("ofac_csl", "error", message="TRADE_GOV_API_KEY not set")
    url = "https://search.api.trade.gov/v1/consolidated_screening_list/search"
    params = {
        "api_key": settings.trade_gov_api_key.get_secret_value(),
        "name": f"{first} {last}",
        "fuzzy_name": "true",
        "size": "20",
    }
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code in (401, 403):
            return SourceResult("ofac_csl", "error", message="Trade.gov rejected the API key")
        if resp.status_code != 200:
            return SourceResult(
                "ofac_csl", "error", message=f"HTTP {resp.status_code} from Trade.gov CSL"
            )
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SourceResult("ofac_csl", "error", message=f"{type(exc).__name__}: {exc}")

    hits = parse_trade_gov_csl_response(payload)
    if not hits:
        return SourceResult("ofac_csl", "empty", message="not on any consolidated sanctions list")
    total = payload.get("total")
    msg = f"⚠ {len(hits)} sanctions hit(s) of {total}" if total else f"⚠ {len(hits)} hits"
    return SourceResult("ofac_csl", "ok", hits=hits, message=msg)


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


# Registry. Adding a source means adding one async callable here. The order
# defines the default-when-no-flag set: courtlistener + edgar are key-free
# and run by default; opencorporates / fec / ofac_csl require API keys and
# are opted into via --source.
SOURCES: dict[str, Any] = {
    "courtlistener": _search_courtlistener,
    "edgar": _search_edgar,
    "opencorporates": _search_opencorporates,
    "fec": _search_fec,
    "ofac_csl": _search_trade_gov_csl,
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
                f"Available: {', '.join(SOURCES)}. "
                "Default: courtlistener, edgar (the no-auth sources)."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of tables.")
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Append the JSON result as one JSONL record to this case file.",
        ),
    ] = None,
) -> None:
    """Search public-record and people-finder sources for a name."""
    if ctx.invoked_subcommand is not None:
        return

    # Default to the no-auth sources so a fresh install does something
    # useful out of the box. Users can opt into the keyed sources
    # (opencorporates, fec, ofac_csl) via --source.
    chosen = sources or ["courtlistener", "edgar"]
    unknown = [s for s in chosen if s not in SOURCES]
    if unknown:
        raise typer.BadParameter(
            f"Unknown source(s): {', '.join(unknown)}. Available: {', '.join(SOURCES)}.",
            param_hint="--source",
        )

    query = f"{first} {last}" + (f", {state}" if state else "")
    results = asyncio.run(_run_all(first, last, state, chosen))
    all_hits = [h for r in results for h in r.hits]

    payload = {
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
    if output is not None:
        append_jsonl(output, "person", payload)
    if json_output:
        print_json(payload)
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
