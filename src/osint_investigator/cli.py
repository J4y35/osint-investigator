"""Root command-line interface for osint-investigator.

This module wires together the subcommand apps defined under
:mod:`osint_investigator.modules` and exposes a single Typer application
named ``app`` that is registered as a console script in ``pyproject.toml``.

Run ``osint-investigator --help`` after installation to see the full command tree.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.panel import Panel
from rich.text import Text

from osint_investigator import __version__
from osint_investigator.modules import (
    breach_module,
    email_module,
    person_module,
    username_module,
)
from osint_investigator.utils import console, err_console

# ── Root app ──────────────────────────────────────────────────────────────────
app = typer.Typer(
    name="osint-investigator",
    help=(
        "A modern OSINT toolkit for private investigators.\n\n"
        "Each subcommand targets a specific data source. Use --json to emit\n"
        "machine-readable results suitable for piping into jq, files, or other tools."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

# Mount subcommand apps. Each module exposes a Typer instance named ``app``.
app.add_typer(email_module.app, name="email", help="Investigate an email address.")
app.add_typer(person_module.app, name="person", help="Investigate a person (name + locale).")
app.add_typer(username_module.app, name="username", help="Investigate a username across sites.")
app.add_typer(breach_module.app, name="breach", help="Check breach / leak corpora.")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"osint-investigator [bold cyan]v{__version__}[/]")
        raise typer.Exit(0)


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Print version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Global options shared by every subcommand."""
    # Show a friendly banner only when invoked without a subcommand AND not piped.
    if ctx.invoked_subcommand is None and console.is_terminal:
        banner = Text.assemble(
            ("osint-investigator", "bold cyan"),
            (f"  v{__version__}\n", "dim"),
            ("Private-investigator OSINT toolkit\n", ""),
            ("Run `osint-investigator --help` to see all commands.", "dim"),
        )
        console.print(Panel(banner, border_style="cyan", expand=False))


def run() -> None:
    """Convenience entry-point for ``python -m osint_investigator``."""
    try:
        app()
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted by user.[/]")
        raise typer.Exit(130) from None


if __name__ == "__main__":  # pragma: no cover
    run()
