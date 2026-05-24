"""``password`` subcommand — k-anonymity check against HIBP's PwnedPasswords.

Privacy model: **your password never leaves this machine.** We SHA-1 it
locally, send only the *first 5 characters* of the hash to HIBP's
``/range/{prefix}`` endpoint, and scan the returned suffix list locally
for our hash's remaining 35 characters. HIBP cannot learn what password
we checked — only that someone queried that 5-char prefix bucket, which
typically contains ~500 hashes.

This is a different HIBP API than ``breachedaccount`` (used by the
``breach`` command). PwnedPasswords requires **no API key**, has no
authentication, and is free to use for everyone.

Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated

import httpx
import typer

from osint_investigator.config import get_settings
from osint_investigator.retry import retrying_get
from osint_investigator.utils import (
    append_jsonl,
    console,
    err_console,
    print_json,
    utcnow_iso,
)

app = typer.Typer(
    name="password",
    help="Check whether a password has appeared in any known breach (k-anonymity).",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


@dataclass(slots=True)
class PasswordCheck:
    """Result of a k-anonymity check.

    Only the breach count is surfaced — never the password, never even
    the hash. ``count`` is the number of times this exact password has
    appeared across all breaches HIBP has ingested.
    """

    pwned: bool
    count: int
    # Hash prefix (5 chars) is recorded for transparency about what was sent;
    # the full hash is intentionally NOT stored or printed anywhere.
    hash_prefix: str


# ── Pure parser ──────────────────────────────────────────────────────────────


def sha1_password(password: str) -> tuple[str, str]:
    """Hash a password and return ``(prefix5, suffix35)`` in uppercase hex.

    HIBP's range API matches against uppercase hex, so we normalise here.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_pwnedpasswords_range(body: str, target_suffix: str) -> int:
    """Scan HIBP's range response for the count matching ``target_suffix``.

    The response is a CRLF-separated list of ``SUFFIX:COUNT`` lines, where
    each suffix is the last 35 chars of a SHA-1 hash whose first 5 chars
    equal the queried prefix.

    Returns 0 if the suffix is not in the list (password not breached).
    The comparison is case-insensitive — HIBP normally returns uppercase
    suffixes but we don't rely on it.
    """
    needle = target_suffix.upper()
    for raw in body.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count_str = line.partition(":")
        if suffix.strip().upper() == needle:
            try:
                return int(count_str.strip())
            except ValueError:
                return 0
    return 0


# ── Network section ──────────────────────────────────────────────────────────


async def _check_pwned(password: str) -> PasswordCheck:
    """Send the 5-char hash prefix to HIBP and scan the result locally."""
    settings = get_settings()
    prefix, suffix = sha1_password(password)
    url = f"{_HIBP_RANGE_URL}{prefix}"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={
            "User-Agent": settings.user_agent,
            # Opt into "Add-Padding" so HIBP returns a random number of
            # padding entries (a flat 800-1000 hashes per response), which
            # makes side-channel size analysis useless.
            "Add-Padding": "true",
        },
    ) as client:
        resp = await retrying_get(client, url)

    if resp.status_code != 200:
        raise RuntimeError(f"HIBP range API returned HTTP {resp.status_code}")

    count = parse_pwnedpasswords_range(resp.text, suffix)
    return PasswordCheck(pwned=count > 0, count=count, hash_prefix=prefix)


# ── Command ──────────────────────────────────────────────────────────────────


def _read_password(explicit: str | None, from_stdin: bool, prompt_if_missing: bool) -> str:
    """Get the password to check, with three precedence rules.

    Order: ``--password`` flag value > ``--stdin`` > interactive prompt.
    If none of those apply and ``prompt_if_missing`` is False, raise.
    """
    if explicit is not None:
        return explicit
    if from_stdin:
        # Read the first line of stdin; strip trailing newline only.
        return sys.stdin.readline().rstrip("\n").rstrip("\r")
    if prompt_if_missing:
        # typer.prompt is typed as Any in its stubs; coerce explicitly so
        # mypy --strict stays happy. hide_input=True is the secure
        # interactive path — the password never echoes to the terminal.
        entered: str = typer.prompt("Password to check", hide_input=True, confirmation_prompt=False)
        return entered
    raise typer.BadParameter(
        "Provide --password, --stdin, or run interactively.", param_hint="--password"
    )


@app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    password: Annotated[
        str | None,
        typer.Option(
            "--password",
            "-p",
            help=(
                "Password to check. WARNING: passes through your shell history. "
                "Prefer --stdin or the interactive prompt."
            ),
        ),
    ] = None,
    from_stdin: Annotated[
        bool,
        typer.Option(
            "--stdin",
            help="Read the password from stdin instead of an argument. Recommended for scripts.",
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit JSON instead of a Rich panel.")
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
    """Check a password against HIBP's PwnedPasswords corpus.

    Uses **k-anonymity**: only the first 5 characters of the password's
    SHA-1 hash are sent to HIBP. Your password never leaves this machine.
    """
    if ctx.invoked_subcommand is not None:
        return

    pw = _read_password(password, from_stdin, prompt_if_missing=not json_output)
    if not pw:
        raise typer.BadParameter("Password is empty.", param_hint="--password")

    import asyncio

    result = asyncio.run(_check_pwned(pw))
    # Defensive: scrub the in-memory copy as best Python allows.
    pw = ""

    payload = {
        "checked_at": utcnow_iso(),
        "hash_prefix_sent": result.hash_prefix,
        "pwned": result.pwned,
        "breach_count": result.count,
        **{k: v for k, v in asdict(result).items() if k not in {"pwned", "count"}},
    }
    if output is not None:
        append_jsonl(output, "password", payload)
    if json_output:
        print_json(payload)
        return

    if result.pwned:
        console.print(
            f"[bold red]⚠ Password compromised.[/]\n\n"
            f"This password has appeared [bold]{result.count:,}[/] time(s) in known "
            f"data breaches. [bold]Stop using it everywhere immediately[/] and rotate "
            f"to a strong unique password (a password manager is the easiest way)."
        )
    else:
        console.print(
            "[bold green]✓ Not found in any HIBP breach.[/]\n\n"
            "That's good news, but no guarantee — HIBP only knows about breaches it's "
            "ingested. Keep using a unique password per site, and a password manager."
        )
    err_console.print(
        f"[dim]Sent hash prefix [cyan]{result.hash_prefix}[/] to HIBP "
        "(k-anonymity — your password never left this machine).[/]"
    )
