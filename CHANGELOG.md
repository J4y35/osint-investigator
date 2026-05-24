# Changelog

All notable changes to **osint-investigator** are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-05-24

### Added

- **New `password` command** — check whether a password has appeared in
  any HIBP breach via [k-anonymity](https://en.wikipedia.org/wiki/K-anonymity).
  Your password never leaves your machine: we SHA-1 it locally, send only
  the first 5 hex chars of the hash to HIBP's free `/range/` endpoint, and
  scan the returned suffix list locally for our hash's remaining 35 chars.
  No API key required. Supports `--password`, `--stdin`, or interactive
  prompt; the interactive mode hides input.
- **Global `--output FILE` flag** on every command — append the JSON
  result as one JSONL record to a case file. Lets an investigator
  accumulate an entire case across multiple invocations into a single
  file that tools like `jq`, `fx`, and `grep` can chew through directly:

  ```
  $ osint-investigator email -e x@y.com  --output case.jsonl
  $ osint-investigator username -u handle --output case.jsonl
  $ osint-investigator breach -q x@y.com  --output case.jsonl
  $ jq 'select(.command == "username")' case.jsonl
  ```
  Each record carries a `command` field and a `recorded_at` timestamp so
  consumers can filter and sort. Parent directories are created on first
  write.

### Quality

- **mypy `--strict` is now a CI merge gate** (was advisory). Cleaned up the
  12 latent type errors that were hiding under `continue-on-error: true`.
- **Coverage reporting** in CI via `pytest-cov`, with a 50% floor. Current
  overall: 51%; parsers ~95%, network paths ~40%.
- **GitHub Actions bumped** from `actions/checkout@v4` + `setup-python@v5`
  to `@v5` + `@v6` to clear the Node 20 deprecation warnings.
- **SECURITY.md** added with responsible-disclosure contact and a 90-day
  default coordinated-disclosure window.

### Tests

130 total now (was 117). New: `test_password.py` covers SHA-1 splitting
and the k-anonymity range parser; `test_smoke.py` covers `append_jsonl`
(record format, parent-dir creation, preserves caller-set `recorded_at`).

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

[0.3.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.3.0
[0.2.1]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.1
[0.2.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.0
[0.1.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.1.0
