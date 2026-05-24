"""Smoke tests — verify the CLI loads and basic validation works.

These do not hit the network. Run with `pytest`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from osint_investigator.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def test_cli_help_loads() -> None:
    """`osint-investigator --help` should exit 0 and mention every subcommand."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.stdout
    for sub in ("email", "person", "username", "breach", "domain"):
        assert sub in result.stdout


def test_domain_rejects_invalid_input() -> None:
    """The domain command should reject obviously-malformed names."""
    result = runner.invoke(app, ["domain", "--domain", "not a domain"])
    assert result.exit_code != 0


def test_version_flag() -> None:
    from osint_investigator import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


@pytest.mark.parametrize("bad", ["", "not-an-email", "foo@", "@bar.com"])
def test_email_rejects_garbage(bad: str) -> None:
    """The email command should reject obviously-invalid addresses."""
    result = runner.invoke(app, ["email", "--email", bad])
    assert result.exit_code != 0


def test_username_list_sites_no_network() -> None:
    """`--list-sites` should print sites and exit without making requests."""
    result = runner.invoke(
        app,
        ["username", "--username", "anyone", "--list-sites", "--site", "github"],
    )
    assert result.exit_code == 0, result.stdout
    assert "GitHub" in result.stdout


def test_clickable_wraps_url_in_rich_link_markup() -> None:
    from osint_investigator.utils import clickable

    assert (
        clickable("https://example.com/x")
        == "[link=https://example.com/x]https://example.com/x[/link]"
    )
    assert (
        clickable("https://example.com/x", display="example")
        == "[link=https://example.com/x]example[/link]"
    )


def test_clickable_passes_through_when_url_missing() -> None:
    from osint_investigator.utils import clickable

    assert clickable(None) == ""
    assert clickable("") == ""
    assert clickable(None, display="fallback") == "fallback"


def test_append_jsonl_writes_one_record_per_line(tmp_path: Path) -> None:
    """append_jsonl should produce a real JSONL file: one JSON object per line."""
    import json as stdlib_json

    from osint_investigator.utils import append_jsonl

    case = tmp_path / "case.jsonl"
    append_jsonl(case, "email", {"query": "a@b.com", "results": [{"name": "x"}]})
    append_jsonl(case, "username", {"query": "alice", "total": 3})
    append_jsonl(case, "breach", {"query": "a@b.com", "total_hits": 1})

    lines = case.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    records = [stdlib_json.loads(line) for line in lines]
    assert [r["command"] for r in records] == ["email", "username", "breach"]
    # Every record gets a recorded_at timestamp.
    assert all("recorded_at" in r for r in records)
    # Payload keys are preserved alongside command + recorded_at.
    assert records[0]["query"] == "a@b.com"
    assert records[1]["total"] == 3


def test_append_jsonl_creates_parent_directories(tmp_path: Path) -> None:
    """A nested path that doesn't exist yet should be created on first append."""
    from osint_investigator.utils import append_jsonl

    nested = tmp_path / "cases" / "2026" / "subject-x.jsonl"
    assert not nested.parent.exists()
    append_jsonl(nested, "email", {"query": "a@b"})
    assert nested.exists()
    assert nested.read_text(encoding="utf-8").endswith("\n")


def test_append_jsonl_does_not_overwrite_existing_recorded_at(tmp_path: Path) -> None:
    """If the caller pre-populates recorded_at, append_jsonl respects it."""
    import json as stdlib_json

    from osint_investigator.utils import append_jsonl

    case = tmp_path / "case.jsonl"
    fixed = "2026-01-01T00:00:00Z"
    append_jsonl(case, "email", {"query": "x", "recorded_at": fixed})
    record = stdlib_json.loads(case.read_text(encoding="utf-8"))
    assert record["recorded_at"] == fixed


def test_username_list_sites_json_serialisable() -> None:
    """Regression: `--list-sites --json` must emit valid JSON.

    Previously ``--json`` fell through to ``ProbeResult.__dict__`` which
    raised because the dataclass uses ``slots=True``; this test pins the
    JSON path for the list-only variant which exercises the same plumbing.
    """
    import json

    result = runner.invoke(
        app,
        ["username", "--username", "anyone", "--list-sites", "--site", "github", "--json"],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["count"] >= 1
    assert any("github" in s.lower() for s in payload["sites"])
