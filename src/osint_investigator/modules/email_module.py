"""``email`` subcommand — check an email across ~120 sites using Holehe.

Holehe exposes a collection of asynchronous probe functions, one per site, all
of which append their result to a shared list. We discover those probes via
``holehe.core.import_submodules`` + ``get_functions`` (the same approach Holehe's
own CLI uses) and run them concurrently with :func:`asyncio.gather`.

A probe's result dictionary looks like::

    {
        "name": "snapchat",        # site identifier
        "domain": "snapchat.com",  # site domain
        "rateLimit": False,        # did Holehe see HTTP 429 / equivalent?
        "exists": True,            # was an account found for this email?
        "emailrecovery": None,     # partially-masked recovery email, if leaked
        "phoneNumber": None,       # partially-masked recovery phone, if leaked
        "others": None,            # any other site-specific metadata
    }
"""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any

import httpx
import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from osint_investigator.config import get_settings
from osint_investigator.utils import console, err_console, print_json, utcnow_iso

app = typer.Typer(
    name="email",
    help="Check whether an email is registered on various services (via Holehe).",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# RFC-5322 is overkill for CLI input. This is the pragmatic regex used by HTML5.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# ── Holehe discovery ─────────────────────────────────────────────────────────
def _load_holehe_probes() -> list[Any]:
    """Discover every Holehe probe function. Cached for the process lifetime."""
    try:
        import holehe.modules as holehe_modules
        from holehe.core import get_functions, import_submodules
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise typer.BadParameter("Holehe is not installed. Run `pip install holehe`.") from exc

    submodules = import_submodules(holehe_modules.__name__)
    # Holehe doesn't ship type stubs, so the return type degrades to Any.
    # Annotate locally so mypy --strict stays happy.
    funcs: list[Any] = get_functions(submodules)
    return funcs


# ── Async runner ─────────────────────────────────────────────────────────────
async def _run_probes(email: str, *, timeout: float) -> list[dict[str, Any]]:
    """Run every Holehe probe against ``email`` concurrently.

    Probe exceptions are swallowed per-probe so a single noisy site doesn't
    bring down the whole run — this mirrors Holehe's own CLI behaviour.
    """
    settings = get_settings()
    probes = _load_holehe_probes()
    results: list[dict[str, Any]] = []

    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        limits=limits,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as client:

        async def _safe(probe: Any) -> None:
            try:
                await probe(email, client, results)
            except Exception as exc:  # noqa: BLE001 - Holehe modules raise broadly
                err_console.print(
                    f"[dim]probe error[/] [yellow]{getattr(probe, '__name__', '?')}[/]: "
                    f"{type(exc).__name__}: {exc}"
                )

        await asyncio.gather(*(_safe(p) for p in probes))

    return results


# ── Output helpers ───────────────────────────────────────────────────────────
def _render_table(email: str, results: list[dict[str, Any]]) -> Table:
    table = Table(title=f"Holehe results for {email}", show_lines=False, expand=False)
    table.add_column("Site", style="cyan", no_wrap=True)
    table.add_column("Exists", justify="center")
    table.add_column("Rate-limited", justify="center")
    table.add_column("Recovery email", style="dim")
    table.add_column("Recovery phone", style="dim")

    for r in sorted(results, key=lambda r: r.get("name", "")):
        exists = r.get("exists")
        if exists is True:
            exists_cell = "[bold green]✓[/]"
        elif exists is False:
            exists_cell = "[red]✗[/]"
        else:
            exists_cell = "[dim]?[/]"
        rate_cell = "[yellow]●[/]" if r.get("rateLimit") else "[dim]-[/]"
        table.add_row(
            r.get("name") or r.get("domain") or "?",
            exists_cell,
            rate_cell,
            r.get("emailrecovery") or "",
            r.get("phoneNumber") or "",
        )
    return table


def _summary(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total_modules": len(results),
        "found": sum(1 for r in results if r.get("exists") is True),
        "not_found": sum(1 for r in results if r.get("exists") is False),
        "rate_limited": sum(1 for r in results if r.get("rateLimit")),
    }


# ── Command ──────────────────────────────────────────────────────────────────
@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    email: Annotated[
        str,
        typer.Option(
            "--email",
            "-e",
            help="Email address to investigate.",
            prompt=False,
            show_default=False,
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit a single JSON document instead of a table."),
    ] = False,
    only_found: Annotated[
        bool,
        typer.Option("--only-found", help="Hide rows where the email was not found."),
    ] = False,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", help="Per-request HTTP timeout (seconds)."),
    ] = None,
) -> None:
    """Check an email across every Holehe-supported site."""
    if ctx.invoked_subcommand is not None:
        return

    if not _EMAIL_RE.match(email):
        raise typer.BadParameter(f"Not a valid email address: {email!r}", param_hint="--email")

    settings = get_settings()
    effective_timeout = timeout if timeout is not None else settings.http_timeout

    # Run with a spinner unless JSON was requested (we want clean stdout for piping).
    if json_output:
        results = asyncio.run(_run_probes(email, timeout=effective_timeout))
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[bold]Probing[/] [cyan]{email}[/] across Holehe sites…"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("holehe", total=None)
            results = asyncio.run(_run_probes(email, timeout=effective_timeout))

    if only_found:
        results = [r for r in results if r.get("exists") is True]

    if json_output:
        payload = {
            "query": email,
            "checked_at": utcnow_iso(),
            **_summary(results),
            "results": sorted(results, key=lambda r: r.get("name", "")),
        }
        print_json(payload)
        return

    console.print(_render_table(email, results))
    s = _summary(results)
    console.print(
        f"\n[bold]Summary:[/] [green]{s['found']}[/] hit · "
        f"[red]{s['not_found']}[/] miss · "
        f"[yellow]{s['rate_limited']}[/] rate-limited · "
        f"[cyan]{s['total_modules']}[/] total"
    )
