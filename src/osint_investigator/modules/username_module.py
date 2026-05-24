"""``username`` subcommand — check whether a handle is taken on common sites.

Probes are loaded from the bundled Sherlock catalogue (see
:mod:`osint_investigator.modules.sherlock_sites`). The catalogue ships with
the package, so the command works offline against ~470 sites.

Probe modes follow Sherlock's documented schema:

- ``status_code``: a 200 response means the profile exists; non-200 (or any
  status listed in ``errorCode``) means it doesn't.
- ``message``: the response body is searched for one or more "not found"
  marker strings. If any marker appears, the profile doesn't exist.
- ``response_url``: redirects are followed; if the final URL matches
  ``errorUrl``, the profile doesn't exist.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.table import Table

from osint_investigator.config import get_settings
from osint_investigator.modules.sherlock_sites import (
    SiteProbe,
    load_all_sites,
    select_sites,
)
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
    name="username",
    help="Check whether a username exists on common social platforms.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Generous syntactic validation — individual sites' regexCheck still applies.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")


@dataclass(slots=True)
class ProbeResult:
    site: str
    url: str
    exists: bool | None
    status: int | None
    error: str | None = None


def _classify(probe: SiteProbe, resp: httpx.Response) -> bool | None:
    """Map an HTTP response to ``exists`` per the probe's error mode.

    Returns ``True`` (exists), ``False`` (does not exist), or ``None``
    (ambiguous — e.g. 5xx server error, unexpected redirect).
    """
    status = resp.status_code
    if probe.error_type == "status_code":
        # Sites with an explicit `errorCode` use *that* code as the negative
        # signal: matching the code means "not found", anything else means
        # "found". This is how Sherlock disambiguates sites that return 200
        # for both states but a distinct code (e.g. 410) for missing users.
        if probe.error_status_codes:
            if status in probe.error_status_codes:
                return False
            if 200 <= status < 400:
                return True
            return None
        # Default semantics: 200 → exists, 4xx → free, 5xx → ambiguous.
        if status == 200:
            return True
        if 400 <= status < 500:
            return False
        return None
    if probe.error_type == "message":
        if any(msg in resp.text for msg in probe.error_messages):
            return False
        if status == 200:
            return True
        # Non-200 with no marker hit is ambiguous — don't claim "free".
        return None
    if probe.error_type == "response_url":
        # Sherlock semantics: the redirect-after-not-found URL is matched
        # *exactly* against the final URL (modulo a trailing slash, which is
        # the only inconsistency seen in the wild). Substring/prefix matching
        # is too aggressive — many sites redirect to a path *under* the home
        # URL when the profile exists.
        target = (probe.error_url or "").rstrip("/")
        final = str(resp.url).rstrip("/")
        return not (target and final == target)
    return None


async def _probe(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    p: SiteProbe,
    username: str,
) -> ProbeResult:
    """Run a single probe under the global concurrency cap."""
    settings = get_settings()
    profile_url = p.profile_url(username)
    probe_url = p.probe_url(username)

    # Honour the site's own regex hint when present — saves an HTTP call and
    # avoids false-positive "free" results for sites that would reject the
    # name as malformed.
    if p.regex_check is not None and not p.regex_check.match(username):
        return ProbeResult(p.name, profile_url, False, None, error="regexCheck mismatch")

    async with semaphore:
        try:
            await async_polite_sleep(settings.request_delay)
            resp = await client.get(probe_url, headers=p.headers or None, follow_redirects=True)
            return ProbeResult(p.name, profile_url, _classify(p, resp), resp.status_code)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                p.name, profile_url, None, None, error=f"{type(exc).__name__}: {exc}"
            )


async def _run(username: str, probes: list[SiteProbe], concurrency: int) -> list[ProbeResult]:
    settings = get_settings()
    semaphore = asyncio.Semaphore(max(1, concurrency))
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={"User-Agent": settings.user_agent},
        http2=False,
    ) as client:
        return await asyncio.gather(*(_probe(client, semaphore, p, username) for p in probes))


def _render_table(username: str, results: list[ProbeResult]) -> Table:
    table = Table(title=f"Username '{username}' across {len(results)} sites", show_lines=False)
    table.add_column("Site", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("HTTP", justify="right", style="dim")
    table.add_column("URL", overflow="fold", style="dim")
    for r in results:
        if r.exists is True:
            tag = "[bold green]TAKEN[/]"
        elif r.exists is False:
            tag = "[red]free[/]"
        else:
            tag = "[yellow]?[/]"
        table.add_row(r.site, tag, str(r.status or "-"), clickable(r.url))
    return table


@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    username: Annotated[str, typer.Option("--username", "-u", help="Username/handle to look up.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of a table.")
    ] = False,
    all_sites: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Check every site in the bundled Sherlock catalogue (~470).",
        ),
    ] = False,
    site: Annotated[
        list[str] | None,
        typer.Option(
            "--site",
            "-s",
            help=(
                "Restrict to sites whose name contains this substring (case-insensitive). "
                "Repeat to allow multiple."
            ),
        ),
    ] = None,
    top: Annotated[
        int | None,
        typer.Option(
            "--top",
            help="Truncate to the first N sites (after filtering).",
            min=1,
        ),
    ] = None,
    include_nsfw: Annotated[
        bool,
        typer.Option("--include-nsfw", help="Include sites Sherlock marks NSFW."),
    ] = False,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency",
            "-c",
            help="Max simultaneous in-flight requests.",
            min=1,
            max=200,
        ),
    ] = 25,
    list_sites: Annotated[
        bool,
        typer.Option(
            "--list-sites",
            help="Print the sites that would be checked and exit (no requests sent).",
        ),
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
    """Check a username across the bundled Sherlock catalogue."""
    if ctx.invoked_subcommand is not None:
        return

    if not _USERNAME_RE.match(username):
        raise typer.BadParameter(f"Invalid username: {username!r}", param_hint="--username")

    probes = select_sites(
        all_sites=all_sites,
        site_filters=tuple(site or ()),
        top=top,
        include_nsfw=include_nsfw,
    )

    if not probes:
        err_console.print(
            "[yellow]No sites matched your filters.[/] "
            f"Catalogue contains {len(load_all_sites())} supportable sites."
        )
        raise typer.Exit(1)

    if list_sites:
        list_payload = {"count": len(probes), "sites": [p.name for p in probes]}
        if output is not None:
            append_jsonl(output, "username:list", list_payload)
        if json_output:
            print_json(list_payload)
        else:
            console.print(f"[bold]{len(probes)} site(s) would be checked:[/]")
            for p in probes:
                tag = " [red](NSFW)[/]" if p.nsfw else ""
                console.print(f"  • {p.name}{tag}  [dim]{p.url_template}[/]")
        return

    results = asyncio.run(_run(username, probes, concurrency))

    payload = {
        "query": username,
        "checked_at": utcnow_iso(),
        "total": len(results),
        "taken": sum(1 for r in results if r.exists is True),
        "concurrency": concurrency,
        # asdict() is needed because ProbeResult uses `slots=True`,
        # which means it has no `__dict__`.
        "results": [asdict(r) for r in results],
    }
    if output is not None:
        append_jsonl(output, "username", payload)
    if json_output:
        print_json(payload)
        return

    console.print(_render_table(username, results))
    taken = sum(1 for r in results if r.exists is True)
    free = sum(1 for r in results if r.exists is False)
    ambiguous = sum(1 for r in results if r.exists is None)
    console.print(
        f"\n[bold]Summary:[/] [green]{taken} taken[/] / "
        f"[red]{free} free[/] / [yellow]{ambiguous} unknown[/] of {len(results)} checked."
    )
