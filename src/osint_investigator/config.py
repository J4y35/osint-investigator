"""Centralised configuration for osint-investigator.

Settings are read from environment variables and `.env`. The schema below is
the single source of truth — add a field here and it will be picked up
everywhere via :func:`get_settings`.

We use `pydantic-settings` because it gives us:
- Typed access (no `os.getenv` typos),
- Automatic `.env` loading,
- Validation on startup so misconfiguration fails loudly.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings backed by environment variables / `.env`."""

    # ── API keys (all optional — modules check before using) ─────────────────
    hibp_api_key: SecretStr | None = Field(default=None, alias="HIBP_API_KEY")
    hunter_api_key: SecretStr | None = Field(default=None, alias="HUNTER_API_KEY")
    intelx_api_key: SecretStr | None = Field(default=None, alias="INTELX_API_KEY")

    # ── Polite scraping defaults ─────────────────────────────────────────────
    user_agent: str = Field(
        default="osint-investigator/0.1 (+https://github.com/J4y35/osint-investigator)",
        alias="OSINT_USER_AGENT",
    )
    request_delay: float = Field(default=1.5, alias="OSINT_REQUEST_DELAY", ge=0.0)
    http_timeout: float = Field(default=20.0, alias="OSINT_HTTP_TIMEOUT", gt=0.0)
    playwright_headless: bool = Field(default=True, alias="OSINT_PLAYWRIGHT_HEADLESS")

    # ── I/O ──────────────────────────────────────────────────────────────────
    output_dir: Path = Field(default=Path("./output"), alias="OSINT_OUTPUT_DIR")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Convenience helpers ──────────────────────────────────────────────────
    def ensure_output_dir(self) -> Path:
        """Create the output directory if missing, return its absolute path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir.resolve()

    def default_headers(self) -> dict[str, str]:
        """Default HTTP headers for all outgoing requests."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance.

    Cached so that repeated lookups across modules don't re-parse `.env`.
    """
    return Settings()  # type: ignore[call-arg]
