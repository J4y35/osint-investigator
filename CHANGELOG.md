# Changelog

All notable changes to **osint-investigator** are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-05-23

### Added

- **Clickable hyperlinks in CLI tables.** URLs in `username`, `person`,
  `breach`, and `domain` outputs are now wrapped in Rich's link markup,
  which emits OSC-8 escape sequences. Terminals that support them
  (iTerm2, recent macOS Terminal.app, Windows Terminal, VS Code's
  terminal, Kitty, Alacritty, WezTerm, etc.) let you ⌘-click (or
  Ctrl-click) the URL to open it in your default browser instead of
  copy-pasting. Subdomain hostnames from CT logs get an `https://`
  prefix so they're clickable too. JSON output is unchanged (plain URL
  strings); piped output also stays plain because Rich strips control
  sequences automatically when stdout isn't a TTY.

## [0.2.0] — 2026-05-23

### Added

- **New `domain` command** — investigate a domain across three sections,
  selectable via repeatable `--section`:
  - **RDAP** via `rdap.org` (no auth) — registrar, registration /
    expiration / last-changed dates, status flags, nameservers.
  - **DNS** via `dnspython` async resolver — A, AAAA, MX, NS, TXT, CAA
    in parallel; per-type failures don't poison the rest.
  - **Subdomains** via `crt.sh` Certificate Transparency log search —
    multi-SAN rows split, wildcards stripped, apex-filtered, deduped,
    sorted.
- **CourtListener source for `person`** — free v4 RECAP API, returns
  federal court dockets where the subject's name appears as a party.
  No auth required.
- **Sherlock catalogue for `username`** — ~460 sites bundled in the
  wheel, replacing the hand-rolled 9-site probe list. New filters:
  `--all`, `--site` (repeatable substring), `--top N`, `--include-nsfw`,
  `--concurrency`, `--list-sites`.
- **Shared retry helper** (`osint_investigator.retry.retrying_get`) —
  exponential-backoff retries on 429 / 5xx / timeouts / network errors,
  wired into HIBP, CourtListener, rdap.org, and crt.sh calls.
- **Explicit per-source status** for `breach`, `person`, and `domain` —
  CLI distinguishes "no matches" from "blocked", "rate limited", or
  "no auth" instead of silently returning nothing.
- **Cloudflare interstitial detection** for the cyberbackgroundchecks
  scraper — reports `blocked` with a clear message rather than
  silently returning zero hits.
- **84 new tests** across `sherlock_sites`, `username_classify`,
  `person_parsers`, `domain_parsers`, `breach_parsers`, and `retry`.
  Fixture-based, no network in CI.

### Changed

- `breach` JSON output now includes a `source_status` array alongside
  `results`, mirroring `person`.
- `person` now defaults to `--source courtlistener`; pass
  `--source cyberbackgroundchecks` (or both) to opt into the Playwright
  scrape.

### Fixed

- `username --json` no longer crashes on `ProbeResult.__dict__` —
  the dataclass uses `slots=True`, so we serialise via
  `dataclasses.asdict()` now.
- `username` no longer fires ~460 simultaneous requests on `--all`;
  default concurrency cap is 25, configurable via `--concurrency`.

## [0.1.0] — 2026-05-22

### Added

- Initial public release with `email` (Holehe), `username` (9-site
  hand-rolled probe), `person` (cyberbackgroundchecks Playwright
  scaffold), and `breach` (HIBP + DDoSecrets) commands.
- CI on Python 3.10/3.11/3.12 × ubuntu/macos.
- MIT license, code of conduct, contributing guide, issue templates.

[0.2.1]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.1
[0.2.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.0
[0.1.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.1.0
