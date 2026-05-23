"""Smoke tests — verify the CLI loads and basic validation works.

These do not hit the network. Run with `pytest`.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from osint_investigator.cli import app

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
