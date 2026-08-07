"""osint-investigator — a modern OSINT CLI for private investigation work.

This package exposes a Typer-based command line interface (`osint-investigator`)
with modular subcommands under `osint_investigator.modules.*`.

The package version is read from installed distribution metadata, so
``pyproject.toml`` is the single source of truth and the value here can never
drift out of sync with the released version.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__: str = version("osint-investigator")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    # Running straight from a checkout that was never pip-installed. Use an
    # obviously-bogus sentinel rather than a literal that could go stale.
    __version__ = "0.0.0+unknown"
