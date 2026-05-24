"""``profile`` subcommand — aggregator that runs every relevant lookup for a subject.

Most investigators end up running four or five separate commands against
the same person and gluing the output together by hand. This command
turns that into one invocation: pass any subset of ``--email``,
``--username``, ``--first/--last``, ``--domain`` and the relevant
upstream modules run in parallel, then a single Markdown report (or
JSON document, or JSONL case-file append) is produced.

Each input triggers a specific subset:

- ``--email``         → ``email`` (Holehe probes) + ``breach`` (HIBP +
                        DDoSecrets) for the same address.
- ``--username``      → ``username`` against the curated Sherlock default
                        set.
- ``--first / --last``→ ``person`` (CourtListener federal court records).
- ``--domain``        → ``domain`` (RDAP + DNS + crt.sh subdomains).

Sections that aren't requested simply don't run. Pass at least one input
flag or the command refuses.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from rich.markdown import Markdown

from osint_investigator.config import get_settings
from osint_investigator.modules import (
    breach_module,
    domain_module,
    email_module,
    person_module,
    username_module,
)
from osint_investigator.modules.sherlock_sites import select_sites
from osint_investigator.utils import (
    append_jsonl,
    console,
    err_console,
    print_json,
    utcnow_iso,
)

app = typer.Typer(
    name="profile",
    help="Aggregate every relevant lookup for a subject into one Markdown report.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


# ── Orchestration ────────────────────────────────────────────────────────────


async def _run_profile(
    *,
    email: str | None,
    username: str | None,
    first: str | None,
    last: str | None,
    state: str | None,
    domain: str | None,
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    """Run the relevant subset of source modules in parallel.

    Returns a dict keyed by section name; missing keys = section not run.
    The async tasks share no client (each module manages its own httpx
    AsyncClient), which keeps concerns separate at the small cost of a
    few extra socket handshakes.
    """
    tasks: dict[str, Any] = {}

    # Breach + email Holehe can both reuse a single shared httpx client.
    # We special-case breach because its `_run_all` builds its own client
    # — fine, just one more handshake.
    if email:
        tasks["email_holehe"] = email_module._run_probes(email, timeout=timeout)
        tasks["email_breach"] = breach_module._run_all(email)

    if username:
        probes = select_sites()  # curated default set — fast (~30 sites)
        tasks["username"] = username_module._run(username, probes, concurrency)

    if first and last:
        tasks["person"] = person_module._run_all(first, last, state, ["courtlistener"])

    if domain:
        tasks["domain"] = domain_module._run(domain, ["rdap", "dns", "subdomains"])

    keys = list(tasks.keys())
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    return dict(zip(keys, results, strict=True))


# ── Markdown report ──────────────────────────────────────────────────────────


def _md_email_holehe(rows: list[dict[str, Any]]) -> str:
    found = [r for r in rows if r.get("exists") is True]
    out = [f"### Email accounts (Holehe) — {len(found)} found of {len(rows)} probed", ""]
    if not found:
        out.append("_No accounts identified across the Holehe site list._")
        return "\n".join(out)
    out.append("| Site | Recovery email | Recovery phone |")
    out.append("| --- | --- | --- |")
    for r in sorted(found, key=lambda x: x.get("name", "")):
        out.append(
            f"| {r.get('name') or r.get('domain') or '?'} "
            f"| {r.get('emailrecovery') or ''} "
            f"| {r.get('phoneNumber') or ''} |"
        )
    return "\n".join(out)


def _md_breach(results: list[Any]) -> str:
    all_hits = [h for r in results for h in r.hits]
    out = [f"### Breach corpora — {len(all_hits)} hit(s)", ""]
    for r in results:
        out.append(f"- **{r.source}**: `{r.status}` — {r.message or ''}")
    if all_hits:
        out.append("")
        out.append("| Source | Name | Date | URL |")
        out.append("| --- | --- | --- | --- |")
        for h in all_hits:
            out.append(f"| {h.source} | {h.name} | {h.date or ''} | {h.url or ''} |")
    return "\n".join(out)


def _md_username(results: list[Any]) -> str:
    taken = [r for r in results if r.exists is True]
    out = [
        f"### Username across {len(results)} sites — {len(taken)} taken",
        "",
    ]
    if not taken:
        out.append("_Handle not found on any curated site._")
        return "\n".join(out)
    out.append("| Site | URL |")
    out.append("| --- | --- |")
    for r in sorted(taken, key=lambda x: x.site.lower()):
        out.append(f"| {r.site} | {r.url} |")
    return "\n".join(out)


def _md_person(results: list[Any]) -> str:
    all_hits = [h for r in results for h in r.hits]
    out = [f"### Person — public records ({len(all_hits)} hit(s))", ""]
    for r in results:
        out.append(f"- **{r.source}**: `{r.status}` — {r.message or ''}")
    if all_hits:
        out.append("")
        out.append("| Source | Case / name | Court / location | URL |")
        out.append("| --- | --- | --- | --- |")
        for h in all_hits[:25]:  # cap to keep the report readable
            out.append(f"| {h.source} | {h.name} | {h.location or ''} | {h.url or ''} |")
        if len(all_hits) > 25:
            out.append(
                f"\n_…{len(all_hits) - 25} more hits truncated; run `person` directly for the full list._"
            )
    return "\n".join(out)


def _md_domain(results: list[Any]) -> str:
    out = ["### Domain", ""]
    for r in results:
        out.append(f"#### {r.section} — `{r.status}`")
        if r.message:
            out.append(f"_{r.message}_")
        out.append("")
        if r.section == "rdap" and r.payload:
            p = r.payload
            out.append(f"- **Registrar:** {p.get('registrar') or '-'}")
            out.append(f"- **Registered:** {p.get('registration_date') or '-'}")
            out.append(f"- **Expires:** {p.get('expiration_date') or '-'}")
            out.append(f"- **Status:** {', '.join(p.get('status') or []) or '-'}")
            ns = p.get("nameservers") or []
            if ns:
                out.append("- **Nameservers:**")
                for n in ns:
                    out.append(f"  - {n}")
        elif r.section == "dns" and r.payload:
            records = r.payload.get("records") or {}
            for rtype, values in records.items():
                out.append(f"- **{rtype}:**")
                for v in values:
                    out.append(f"  - `{v}`")
        elif r.section == "subdomains" and r.payload:
            subs = r.payload.get("subdomains") or []
            out.append(f"- **{len(subs)} subdomain(s) from CT logs:**")
            for s in subs[:25]:
                out.append(f"  - {s}")
            if len(subs) > 25:
                out.append(f"  - _…{len(subs) - 25} more truncated_")
        out.append("")
    return "\n".join(out)


def _render_markdown(query: dict[str, Any], sections: dict[str, Any]) -> str:
    """Assemble the full Markdown report from the orchestrator output."""
    parts: list[str] = []
    parts.append("# Profile report")
    parts.append("")
    parts.append(f"**Generated:** `{utcnow_iso()}`")
    parts.append("")
    parts.append("## Subject")
    parts.append("")
    for label, value in query.items():
        if value:
            parts.append(f"- **{label}:** `{value}`")
    parts.append("")
    parts.append("---")
    parts.append("")

    if "email_holehe" in sections:
        result = sections["email_holehe"]
        if isinstance(result, Exception):
            parts.append(f"### Email accounts — **error**: {type(result).__name__}: {result}")
        else:
            parts.append(_md_email_holehe(result))
        parts.append("")
    if "email_breach" in sections:
        result = sections["email_breach"]
        if isinstance(result, Exception):
            parts.append(f"### Breach corpora — **error**: {type(result).__name__}: {result}")
        else:
            parts.append(_md_breach(result))
        parts.append("")
    if "username" in sections:
        result = sections["username"]
        if isinstance(result, Exception):
            parts.append(f"### Username — **error**: {type(result).__name__}: {result}")
        else:
            parts.append(_md_username(result))
        parts.append("")
    if "person" in sections:
        result = sections["person"]
        if isinstance(result, Exception):
            parts.append(f"### Person — **error**: {type(result).__name__}: {result}")
        else:
            parts.append(_md_person(result))
        parts.append("")
    if "domain" in sections:
        result = sections["domain"]
        if isinstance(result, Exception):
            parts.append(f"### Domain — **error**: {type(result).__name__}: {result}")
        else:
            parts.append(_md_domain(result))
        parts.append("")
    return "\n".join(parts)


# ── Convert orchestrator results to a JSON-safe dict ─────────────────────────


def _serialise_sections(sections: dict[str, Any]) -> dict[str, Any]:
    """Turn dataclasses + exceptions into JSON-encodable shapes."""
    out: dict[str, Any] = {}
    for key, value in sections.items():
        if isinstance(value, Exception):
            out[key] = {"error": f"{type(value).__name__}: {value}"}
        elif isinstance(value, list):
            out[key] = [
                asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in value
            ]
        else:
            out[key] = value
    return out


# ── Command ──────────────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def profile(
    ctx: typer.Context,
    email: Annotated[
        str | None, typer.Option("--email", "-e", help="Email to investigate.")
    ] = None,
    username: Annotated[
        str | None, typer.Option("--username", "-u", help="Username/handle to investigate.")
    ] = None,
    first: Annotated[
        str | None, typer.Option("--first", "-f", help="First name (paired with --last).")
    ] = None,
    last: Annotated[
        str | None, typer.Option("--last", "-l", help="Last name (paired with --first).")
    ] = None,
    state: Annotated[
        str | None,
        typer.Option(
            "--state", "-s", help="Two-letter US state code (folded into the person query)."
        ),
    ] = None,
    domain: Annotated[
        str | None, typer.Option("--domain", "-d", help="Domain to investigate.")
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", help="Username probe concurrency.", min=1, max=200),
    ] = 25,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", help="Per-request HTTP timeout (seconds)."),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the combined JSON document instead of Markdown.")
    ] = False,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report", help="Write the Markdown report to this file (in addition to stdout)."
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Append the combined JSON as one JSONL record to this case file.",
        ),
    ] = None,
) -> None:
    """Run every relevant lookup for a subject and emit one consolidated report.

    Pass at least one input flag: ``--email``, ``--username``, both
    ``--first`` and ``--last``, or ``--domain``.
    """
    if ctx.invoked_subcommand is not None:
        return

    # At least one input must be provided.
    if not (email or username or (first and last) or domain):
        raise typer.BadParameter(
            "Pass at least one of --email, --username, --first/--last, or --domain.",
            param_hint="--email/--username/--first/--last/--domain",
        )
    if (first and not last) or (last and not first):
        raise typer.BadParameter(
            "--first and --last must be used together.",
            param_hint="--first/--last",
        )

    settings = get_settings()
    effective_timeout = timeout if timeout is not None else settings.http_timeout

    sections = asyncio.run(
        _run_profile(
            email=email,
            username=username,
            first=first,
            last=last,
            state=state,
            domain=domain,
            concurrency=concurrency,
            timeout=effective_timeout,
        )
    )

    query = {
        "email": email,
        "username": username,
        "first": first,
        "last": last,
        "state": state,
        "domain": domain,
    }

    payload: dict[str, Any] = {
        "query": query,
        "checked_at": utcnow_iso(),
        "sections": _serialise_sections(sections),
    }

    if output is not None:
        append_jsonl(output, "profile", payload)

    if json_output:
        print_json(payload)
        return

    md = _render_markdown({k: v for k, v in query.items() if v}, sections)

    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(md, encoding="utf-8")
        err_console.print(f"[dim]Wrote Markdown report to {report}[/]")

    console.print(Markdown(md))


# Silence the linter — we import the runtime ``httpx`` only because tasks/...
# below need it implicitly via the module-level type hints.
_ = httpx
