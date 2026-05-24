"""Loader for the bundled Sherlock site catalogue.

We ship a snapshot of `sherlock-project/sherlock`'s ``data.json`` so the
``username`` command works fully offline. This module normalises the raw
Sherlock schema into a small :class:`SiteProbe` dataclass that the probing
code can consume without caring about Sherlock-isms (string-vs-list
``errorMsg``, ``urlProbe`` overrides, etc.).

Schema reference (Sherlock):
- ``errorType`` ∈ ``{"status_code", "message", "response_url"}``
- ``url``: canonical profile URL with ``{}`` placeholder for the username
- ``urlMain``: site homepage (informational)
- ``urlProbe``: optional alternate URL to actually GET (e.g. an API endpoint)
- ``errorMsg``: substring(s) that mean *not* found (when errorType=message);
  can be a single string or a list of strings — we always normalise to a list
- ``errorUrl``: redirect target meaning *not* found (when errorType=response_url)
- ``errorCode``: status code that explicitly means *not* found (status_code type)
- ``regexCheck``: optional per-site username regex
- ``request_method``: optional HTTP verb (mostly GET; we skip POST sites)
- ``isNSFW``: bool — surfaced through :attr:`SiteProbe.nsfw`
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Literal

# Sherlock's three documented error-detection modes.
ErrorType = Literal["status_code", "message", "response_url"]


@dataclass(slots=True, frozen=True)
class SiteProbe:
    """A normalised, Sherlock-derived site probe descriptor."""

    name: str
    url_template: str  # canonical profile URL with `{}` placeholder
    probe_url_template: str  # URL we actually GET (== url_template unless urlProbe set)
    error_type: ErrorType
    error_messages: tuple[str, ...] = ()  # populated when error_type == "message"
    error_url: str | None = None  # populated when error_type == "response_url"
    error_status_codes: tuple[int, ...] = ()  # explicit "not found" codes
    regex_check: re.Pattern[str] | None = None
    nsfw: bool = False
    headers: dict[str, str] = field(default_factory=dict)

    def profile_url(self, username: str) -> str:
        """The canonical profile URL — what we surface in output."""
        return self.url_template.format(username)

    def probe_url(self, username: str) -> str:
        """The URL we actually request (may differ from the profile URL)."""
        return self.probe_url_template.format(username)


def _coerce_error_messages(raw: object) -> tuple[str, ...]:
    """Sherlock's ``errorMsg`` is sometimes a string, sometimes a list."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list):
        return tuple(str(x) for x in raw)
    return ()


def _coerce_error_codes(raw: object) -> tuple[int, ...]:
    """``errorCode`` is documented as an int but be defensive about lists."""
    if raw is None:
        return ()
    if isinstance(raw, int):
        return (raw,)
    if isinstance(raw, list):
        return tuple(int(x) for x in raw if isinstance(x, int))
    return ()


def _build_probe(name: str, entry: dict[str, object]) -> SiteProbe | None:
    """Convert one Sherlock entry into a :class:`SiteProbe`.

    Returns ``None`` if the entry isn't supportable (e.g. POST-only sites we
    don't yet implement, or malformed entries).
    """
    method = str(entry.get("request_method", "GET")).upper()
    if method != "GET":
        # POST endpoints with request_payload are uncommon (~3 sites) and
        # require a different probe path. Skip rather than silently misreport.
        return None

    url = entry.get("url")
    error_type = entry.get("errorType")
    if not isinstance(url, str) or error_type not in ("status_code", "message", "response_url"):
        return None

    url_probe = entry.get("urlProbe")
    probe_url = url_probe if isinstance(url_probe, str) else url

    # We need a `{}` placeholder somewhere to actually probe per-username.
    # A handful of Sherlock entries point `url` at a site homepage and rely on
    # downstream logic we don't replicate — skip them rather than silently
    # GET-ing the homepage for every lookup.
    if "{}" not in probe_url:
        return None

    regex_raw = entry.get("regexCheck")
    try:
        regex = re.compile(regex_raw) if isinstance(regex_raw, str) else None
    except re.error:
        # A handful of Sherlock regexes have been known to break across Python
        # versions; skip the regex rather than failing site loading entirely.
        regex = None

    headers_raw = entry.get("headers")
    headers: dict[str, str] = (
        {str(k): str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}
    )

    error_url_raw = entry.get("errorUrl")
    return SiteProbe(
        name=name,
        url_template=url,
        probe_url_template=probe_url,
        error_type=error_type,
        error_messages=_coerce_error_messages(entry.get("errorMsg")),
        error_url=error_url_raw if isinstance(error_url_raw, str) else None,
        error_status_codes=_coerce_error_codes(entry.get("errorCode")),
        regex_check=regex,
        nsfw=bool(entry.get("isNSFW", False)),
        headers=headers,
    )


@lru_cache(maxsize=1)
def load_all_sites() -> tuple[SiteProbe, ...]:
    """Return every supportable site in the bundled Sherlock catalogue.

    Cached for the life of the process — the JSON file is ~100 KB and we
    parse it once.
    """
    resource = files("osint_investigator.data").joinpath("data.json")
    raw = json.loads(resource.read_text(encoding="utf-8"))
    probes: list[SiteProbe] = []
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue  # `$schema` and similar meta keys
        probe = _build_probe(name, entry)
        if probe is not None:
            probes.append(probe)
    # Stable alphabetical ordering keeps `--top N` reproducible.
    probes.sort(key=lambda p: p.name.lower())
    return tuple(probes)


# ── Curated default set ──────────────────────────────────────────────────────
# A small list of widely-used platforms that exist in the bundled Sherlock
# catalogue. Used when the user runs ``username`` without ``--all`` or
# ``--site``. Keep this short — the goal is "the obvious places to check
# first", not "everything we possibly could".
DEFAULT_CURATED: tuple[str, ...] = (
    "GitHub",
    "GitLab",
    "Reddit",
    "Twitter",
    "Instagram",
    "TikTok",
    "Medium",
    "Keybase",
    "HackerNews",
    "YouTube",
    "Twitch",
    "Pinterest",
    "Spotify",
    "SoundCloud",
    "Patreon",
    "Vimeo",
    "tumblr",
    "Pastebin",
    "Wikipedia",
    "BitBucket",
    "Codepen",
    "Dribbble",
    "Behance",
    "ProductHunt",
    "Roblox",
    "Discord",
    "Snapchat",
    "threads",
    "Lichess",
    "Chess",
    "Kaggle",
    "HackerOne",
    "BugCrowd",
)


def select_sites(
    *,
    all_sites: bool = False,
    site_filters: tuple[str, ...] = (),
    top: int | None = None,
    include_nsfw: bool = False,
) -> list[SiteProbe]:
    """Pick a subset of probes per the user's flags.

    Precedence:
        1. ``site_filters`` (any of, case-insensitive substring match) wins
           if non-empty.
        2. ``all_sites`` returns the full catalogue.
        3. Otherwise the curated default list is used.

    ``include_nsfw`` is applied last, after the candidate set is chosen.
    ``top`` truncates after ordering/filtering.
    """
    catalogue = load_all_sites()

    if site_filters:
        needles = tuple(s.lower() for s in site_filters)
        candidates = [p for p in catalogue if any(n in p.name.lower() for n in needles)]
    elif all_sites:
        candidates = list(catalogue)
    else:
        wanted = {n.lower() for n in DEFAULT_CURATED}
        candidates = [p for p in catalogue if p.name.lower() in wanted]

    if not include_nsfw:
        candidates = [p for p in candidates if not p.nsfw]

    if top is not None and top > 0:
        candidates = candidates[:top]

    return candidates
