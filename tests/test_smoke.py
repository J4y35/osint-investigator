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
    for sub in ("email", "person", "username", "breach"):
        assert sub in result.stdout


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
