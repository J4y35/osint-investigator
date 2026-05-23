"""``username`` subcommand — check whether a handle is taken on common sites.

This is a deliberately small skeleton; production setups should switch to a
maintained list (e.g. Sherlock's ``data.json``) once you've validated the
core CLI surface. The pattern below is intentionally easy to extend.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Annotated

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
    name="username",
    help="Check whether a username exists on common social platforms.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Username syntactic validation (most sites enforce a similar charset).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")


@dataclass(slots=True)
class SiteProbe:
    """A minimal probe descriptor.

    ``existence`` is a string that, if present in the response body, means the
    username exists; ``absent_marker`` is the inverse. Probes that use HTTP
    status codes alone leave both as ``None``.
    """

    name: str
    url_template: str   # `{}` placeholder for the username
    status_taken: tuple[int, ...] = (200,)
    status_free: tuple[int, ...] = (404,)
    absent_marker: str | None = None  # if substring is in body -> NOT taken


# Starter list. Add sites by appending here.
PROBES: list[SiteProbe] = [
    SiteProbe("GitHub",   "https://github.com/{}",          (200,), (404,)),
    SiteProbe("GitLab",   "https://gitlab.com/{}",          (200,), (404,)),
    SiteProbe("Reddit",   "https://www.reddit.com/user/{}", (200,), (404,)),
    SiteProbe("Twitter",  "https://twitter.com/{}",         (200,), (404,)),
    SiteProbe("Instagram","https://www.instagram.com/{}/",  (200,), (404,)),
    SiteProbe("TikTok",   "https://www.tiktok.com/@{}",     (200,), (404,)),
    SiteProbe("Medium",   "https://medium.com/@{}",         (200,), (404,)),
    SiteProbe("Keybase",  "https://keybase.io/{}",          (200,), (404,)),
    SiteProbe("HackerNews","https://news.ycombinator.com/user?id={}", (200,), (404,),
              absent_marker="No such user."),
]


@dataclass(slots=True)
class ProbeResult:
    site: str
    url: str
    exists: bool | None
    status: int | None
    error: str | None = None


async def _probe(client: httpx.AsyncClient, p: SiteProbe, username: str) -> ProbeResult:
    """Run a single probe with retries handled by httpx defaults."""
    url = p.url_template.format(username)
    settings = get_settings()
    try:
        await async_polite_sleep(settings.request_delay)
        resp = await client.get(url, follow_redirects=True)
        body = resp.text if p.absent_marker else ""
        if p.absent_marker and p.absent_marker in body:
            exists: bool | None = False
        elif resp.status_code in p.status_taken:
            exists = True
        elif resp.status_code in p.status_free:
            exists = False
        else:
            exists = None  # ambiguous
        return ProbeResult(p.name, url, exists, resp.status_code)
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(p.name, url, None, None, error=f"{type(exc).__name__}: {exc}")


async def _run(username: str) -> list[ProbeResult]:
    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={"User-Agent": settings.user_agent},
        http2=False,
    ) as client:
        return await asyncio.gather(*(_probe(client, p, username) for p in PROBES))


def _render_table(username: str, results: list[ProbeResult]) -> Table:
    table = Table(title=f"Username '{username}' across {len(PROBES)} sites", show_lines=False)
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
        table.add_row(r.site, tag, str(r.status or "-"), r.url)
    return table


@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    username: Annotated[str, typer.Option("--username", "-u", help="Username/handle to look up.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of a table.")] = False,
) -> None:
    """Check a username across a curated list of platforms."""
    if ctx.invoked_subcommand is not None:
        return

    if not _USERNAME_RE.match(username):
        raise typer.BadParameter(f"Invalid username: {username!r}", param_hint="--username")

    results = asyncio.run(_run(username))

    if json_output:
        print_json(
            {
                "query": username,
                "checked_at": utcnow_iso(),
                "total": len(results),
                "taken": sum(1 for r in results if r.exists is True),
                "results": [r.__dict__ for r in results],
            }
        )
        return

    console.print(_render_table(username, results))
    taken = sum(1 for r in results if r.exists is True)
    console.print(f"\n[bold]Summary:[/] [green]{taken}[/] taken / {len(results)} checked.")
