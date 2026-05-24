"""osint-investigator — a modern OSINT CLI for private investigation work.

This package exposes a Typer-based command line interface (`osint-investigator`)
with modular subcommands under `osint_investigator.modules.*`.

The package version is defined here so it can be read at runtime without
parsing pyproject.toml.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__: str = "0.2.1"
