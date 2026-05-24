"""``domain`` subcommand — WHOIS/RDAP, DNS records, and subdomain enumeration.

Three independent lookups, each rendered as its own table (or its own
section of the JSON payload). Sections are opt-out via ``--section`` —
when no sections are specified, all three run.

Sources:

- **RDAP** via the public ``rdap.org`` aggregator — modern, JSON-structured
  replacement for WHOIS. No auth required. Returns registrar, dates,
  status flags, and nameservers.
- **DNS** via `dnspython`'s asyncio resolver. Pulls A, AAAA, MX, NS, TXT,
  and CAA records. Each record type is its own lookup so a failure in
  one doesn't poison the rest.
- **crt.sh** Certificate Transparency log search for subdomain
  enumeration. Public JSON endpoint, no auth. Deduplicated and sorted.

All three sections use the :class:`SectionResult` pattern from
:mod:`osint_investigator.modules.person_module` so the CLI surfaces
per-section status (`ok` / `empty` / `error`) rather than silently
returning nothing.
"""

from __future__ import annotations

import asyncio
import re
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
    print_json,
    utcnow_iso,
)

app = typer.Typer(
    name="domain",
    help="Investigate a domain: RDAP/WHOIS, DNS records, and subdomain enumeration.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


# ── Validation ───────────────────────────────────────────────────────────────

# Pragmatic domain regex — RFC-compliant validators exist but they're
# overkill for CLI input sanitisation. This rejects obvious garbage while
# allowing internationalised labels and long TLDs.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip().rstrip(".")))


# ── Data model ───────────────────────────────────────────────────────────────

SectionStatus = Literal["ok", "empty", "error"]
SectionName = Literal["rdap", "dns", "subdomains"]


@dataclass(slots=True)
class SectionResult:
    """Outcome of one section of the domain lookup."""

    section: SectionName
    status: SectionStatus
    payload: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


# ── Pure parsers (tested with fixtures) ──────────────────────────────────────


def parse_rdap_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Distil the parts of an RDAP response useful for an investigator.

    RDAP responses are richly structured; we keep registrar name, key
    dates (registration, expiration, last update), status flags, and the
    nameserver list. Full response is available to callers as needed.
    """
    out: dict[str, Any] = {
        "registrar": None,
        "registration_date": None,
        "expiration_date": None,
        "last_changed": None,
        "status": list(payload.get("status") or []),
        "nameservers": [],
    }

    # Registrar info lives in an `entities` array; the entry with role
    # "registrar" is the one we want. vCard data is nested under `vcardArray`.
    for entity in payload.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            out["registrar"] = _extract_vcard_name(entity.get("vcardArray"))
            break

    for event in payload.get("events") or []:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if not date:
            continue
        if action == "registration":
            out["registration_date"] = date
        elif action == "expiration":
            out["expiration_date"] = date
        elif action in ("last changed", "last update of RDAP database"):
            out["last_changed"] = date

    nameservers: list[str] = []
    for ns in payload.get("nameservers") or []:
        ldh = ns.get("ldhName")
        if ldh:
            nameservers.append(str(ldh).lower())
    # Dedupe while preserving order — some RDAP responses repeat entries.
    seen: set[str] = set()
    out["nameservers"] = [n for n in nameservers if not (n in seen or seen.add(n))]
    return out


def _extract_vcard_name(vcard_array: Any) -> str | None:
    """Pull the ``fn`` field out of a vCard 4.0 JSON structure."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
            return str(entry[3])
    return None


def parse_crtsh_response(payload: list[dict[str, Any]], apex: str) -> list[str]:
    """Pull unique subdomain names from a crt.sh JSON response.

    crt.sh's ``name_value`` field contains one or more hostnames separated
    by newlines (when a cert covers multiple SANs). We dedupe across
    rows, normalise to lowercase, strip wildcard markers, and only keep
    names that end with the apex domain (defence against odd matches).
    """
    out: set[str] = set()
    suffix = "." + apex.lower().lstrip(".")
    for entry in payload:
        raw = entry.get("name_value") or ""
        for line in str(raw).splitlines():
            name = line.strip().lower().lstrip("*.")
            if not name:
                continue
            if name == apex.lower() or name.endswith(suffix):
                out.add(name)
    return sorted(out)


# ── Network sections ─────────────────────────────────────────────────────────


async def _section_rdap(domain: str) -> SectionResult:
    settings = get_settings()
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/rdap+json"},
            follow_redirects=True,
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url)
        if resp.status_code == 404:
            return SectionResult("rdap", "empty", message="domain not found in RDAP")
        if resp.status_code != 200:
            return SectionResult("rdap", "error", message=f"HTTP {resp.status_code} from rdap.org")
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        return SectionResult("rdap", "error", message=f"{type(exc).__name__}: {exc}")

    parsed = parse_rdap_response(payload)
    return SectionResult("rdap", "ok", payload=parsed)


# DNS record types we look up by default. CAA can be slow and many domains
# don't publish it; kept in the list because its presence is a real
# OSINT signal (used to gate which CAs may issue for the domain).
_DNS_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CAA")


async def _section_dns(domain: str) -> SectionResult:
    """Query the standard record types in parallel via dnspython."""
    try:
        import dns.asyncresolver
        import dns.exception
    except ImportError:
        return SectionResult(
            "dns",
            "error",
            message="dnspython not installed (`pip install dnspython`)",
        )

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = float(get_settings().http_timeout)

    async def lookup(rtype: str) -> tuple[str, list[str] | None, str | None]:
        try:
            answer = await resolver.resolve(domain, rtype)
            values = [str(rdata) for rdata in answer]
            return (rtype, values, None)
        except dns.resolver.NoAnswer:
            return (rtype, [], None)
        except dns.resolver.NXDOMAIN:
            return (rtype, None, "NXDOMAIN")
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            return (rtype, None, f"{type(exc).__name__}")

    results = await asyncio.gather(*(lookup(r) for r in _DNS_RECORD_TYPES))

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    nxdomain = False
    for rtype, values, err in results:
        if err == "NXDOMAIN":
            nxdomain = True
        elif err:
            errors[rtype] = err
        elif values is not None:
            records[rtype] = values

    if nxdomain:
        return SectionResult("dns", "empty", message="NXDOMAIN — domain does not resolve")
    payload: dict[str, Any] = {"records": records}
    if errors:
        payload["errors"] = errors
    if not any(records.values()):
        return SectionResult("dns", "empty", payload=payload, message="no records returned")
    return SectionResult("dns", "ok", payload=payload)


async def _section_subdomains(domain: str) -> SectionResult:
    settings = get_settings()
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            await async_polite_sleep(settings.request_delay)
            resp = await retrying_get(client, url, params=params)
        if resp.status_code != 200:
            return SectionResult(
                "subdomains",
                "error",
                message=f"HTTP {resp.status_code} from crt.sh (retries exhausted)",
            )
        # crt.sh occasionally returns an empty body for "no results" rather
        # than `[]`; treat both the same way.
        text = resp.text.strip()
        payload = resp.json() if text else []
    except Exception as exc:  # noqa: BLE001
        return SectionResult("subdomains", "error", message=f"{type(exc).__name__}: {exc}")

    subs = parse_crtsh_response(payload, domain)
    if not subs:
        return SectionResult("subdomains", "empty", message="no certificates found for this domain")
    return SectionResult(
        "subdomains",
        "ok",
        payload={"count": len(subs), "subdomains": subs},
        message=f"{len(subs)} unique names found",
    )


SECTIONS: dict[SectionName, Any] = {
    "rdap": _section_rdap,
    "dns": _section_dns,
    "subdomains": _section_subdomains,
}


# ── Orchestration + rendering ────────────────────────────────────────────────


async def _run(domain: str, sections: list[SectionName]) -> list[SectionResult]:
    return await asyncio.gather(*(SECTIONS[s](domain) for s in sections))


_STATUS_STYLE: dict[SectionStatus, str] = {
    "ok": "[green]ok[/]",
    "empty": "[yellow]empty[/]",
    "error": "[red]error[/]",
}


def _render_rdap(payload: dict[str, Any]) -> Table:
    table = Table(title="RDAP / WHOIS", show_lines=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", overflow="fold")
    table.add_row("Registrar", str(payload.get("registrar") or "-"))
    table.add_row("Registered", str(payload.get("registration_date") or "-"))
    table.add_row("Expires", str(payload.get("expiration_date") or "-"))
    table.add_row("Last changed", str(payload.get("last_changed") or "-"))
    statuses = payload.get("status") or []
    table.add_row("Status", ", ".join(statuses) if statuses else "-")
    ns = payload.get("nameservers") or []
    table.add_row("Nameservers", "\n".join(ns) if ns else "-")
    return table


def _render_dns(payload: dict[str, Any]) -> Table:
    table = Table(title="DNS records", show_lines=False)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Values", overflow="fold")
    for rtype in _DNS_RECORD_TYPES:
        values = (payload.get("records") or {}).get(rtype) or []
        table.add_row(rtype, "\n".join(values) if values else "-")
    return table


def _render_subdomains(payload: dict[str, Any]) -> Table:
    subs = payload.get("subdomains") or []
    table = Table(
        title=f"Subdomains (from CT logs) — {len(subs)} found",
        show_lines=False,
    )
    table.add_column("Subdomain", style="cyan", overflow="fold")
    # CT-log entries are hostnames; prefix https:// so the terminal can open
    # them as URLs. The displayed text stays the plain hostname.
    for s in subs:
        table.add_row(clickable(f"https://{s}", display=s))
    return table


# ── Command ──────────────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def investigate(
    ctx: typer.Context,
    domain: Annotated[
        str, typer.Option("--domain", "-d", help="Domain to investigate (e.g. example.com).")
    ],
    section: Annotated[
        list[str] | None,
        typer.Option(
            "--section",
            "-s",
            help=(
                "Sections to run. Repeat to pick multiple. "
                f"Available: {', '.join(SECTIONS)}. Default: all three."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of tables.")
    ] = False,
) -> None:
    """Investigate a domain across RDAP, DNS, and CT-log subdomain enumeration."""
    if ctx.invoked_subcommand is not None:
        return

    domain_clean = domain.strip().rstrip(".").lower()
    if not is_valid_domain(domain_clean):
        raise typer.BadParameter(f"Invalid domain: {domain!r}", param_hint="--domain")

    chosen: list[SectionName] = []
    if section:
        for s in section:
            if s not in SECTIONS:
                raise typer.BadParameter(
                    f"Unknown section: {s!r}. Available: {', '.join(SECTIONS)}.",
                    param_hint="--section",
                )
            chosen.append(s)  # type: ignore[arg-type]
    else:
        chosen = list(SECTIONS.keys())  # type: ignore[arg-type]

    results = asyncio.run(_run(domain_clean, chosen))

    if json_output:
        print_json(
            {
                "query": {"domain": domain_clean},
                "checked_at": utcnow_iso(),
                "sections": [
                    {
                        "name": r.section,
                        "status": r.status,
                        "message": r.message,
                        **asdict(r),  # exposes payload too; section/status repeat is benign
                    }
                    for r in results
                ],
            }
        )
        return

    for r in results:
        header = f"\n[bold]Section[/] [cyan]{r.section}[/] — {_STATUS_STYLE[r.status]}"
        if r.message:
            header += f"  [dim]({r.message})[/]"
        console.print(header)
        if r.status != "ok":
            continue
        if r.section == "rdap":
            console.print(_render_rdap(r.payload))
        elif r.section == "dns":
            console.print(_render_dns(r.payload))
        elif r.section == "subdomains":
            console.print(_render_subdomains(r.payload))
