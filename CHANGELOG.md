# Changelog

All notable changes to **osint-investigator** are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.1] — 2026-08-04

### Changed

- Raised minimum versions for several core dependencies (typer, playwright, pydantic, tenacity, ruff) to keep the tool on modern, well-supported releases.

## [0.5.0] — 2026-05-24

### Added

Four new public-records sources for the `person` command, each picked
for "legitimate signal about a person from a public-records source that
will not give you their address." Selectable via `--source`; the
no-auth ones run by default.

- **`edgar`** (no auth) — SEC EDGAR full-text search. Returns every
  filing where the subject's name appears: officers and directors of
  public companies, Form 4 insider trades, 13F filings, etc. Live-tested
  against "Warren Buffett" → 100+ hits. Surfaces filing URL, form
  type, file date, and CIK in `extra`.
- **`opencorporates`** (key required: `OPENCORPORATES_API_KEY`) —
  officer / director search across global company registries. Answers
  "is this person on the board of a registered company anywhere in the
  world." Surfaces company, position, jurisdiction, start/end dates.
- **`fec`** (key required: `FEC_API_KEY` — free from api.data.gov) —
  individual political contributions above the $200 federal disclosure
  threshold. Surfaces amount, date, recipient committee, contributor's
  self-reported employer and occupation, and the FEC docket URL.
- **`ofac_csl`** (key required: `TRADE_GOV_API_KEY` — free from
  api.trade.gov) — Trade.gov's consolidated screening list aggregating
  OFAC SDN + BIS Entity List + State Department Debarred List. Any
  hit here is *significant* for due-diligence work. Surfaces sanctions
  program, citizenship, addresses, and the source list URL.

The `profile` aggregator now runs `edgar` alongside `courtlistener` by
default when `--first` / `--last` are passed.

### Quality

- Default `--source` for the `person` command is now
  `["courtlistener", "edgar"]` — both no-auth, both high-signal. The
  three keyed sources are opt-in.
- EDGAR requests send a SEC-compliant plain User-Agent
  (`osint-investigator-cli/<version>`) regardless of the global
  `OSINT_USER_AGENT`. SEC's WAF blocks UAs containing parenthesized
  URLs or `github.com` — patterns common to scrapers — which would
  otherwise return HTTP 403.
- New config fields: `FEC_API_KEY`, `TRADE_GOV_API_KEY`,
  `OPENCORPORATES_API_KEY` (all optional `SecretStr`).

### Tests

154 total now (+12 since v0.4.0). New fixtures + parser tests for
all four sources:

- `tests/fixtures/edgar_sotomayor.json` — real EDGAR response (3 hits).
- `tests/fixtures/opencorporates_officers.json` — hand-crafted matching
  the documented v0.4 schema (3 officerships).
- `tests/fixtures/fec_donor_search.json` — hand-crafted matching the
  documented v1 schema (3 contributions).
- `tests/fixtures/trade_gov_csl.json` — hand-crafted matching the
  documented CSL schema (1 SDN individual + 1 Entity List entity).

Each parser covered for happy path, missing-fields tolerance, and
empty-results handling.

## [0.4.0] — 2026-05-24

### Added

- **New `profile` aggregator command.** One invocation runs every relevant
  module against a subject and emits a single consolidated Markdown report
  (or JSON document, or appends one JSONL record to a case file).

  ```
  $ osint-investigator profile \\
      --email   alice@example.com  \\
      --username alice42           \\
      --first   Alice --last Smith \\
      --domain  example.com        \\
      --report  case.md            \\
      --output  case.jsonl
  ```

  Input flags map to upstream modules:
  - `--email`               → `email` (Holehe) **+** `breach` (HIBP + DDoSecrets)
  - `--username`            → `username` against the curated Sherlock default set
  - `--first` + `--last`    → `person` (CourtListener federal court records)
  - `--domain`              → `domain` (RDAP + DNS + crt.sh subdomains)

  Sections that aren't requested don't run. Sections that error are
  captured (not raised) so one upstream failure doesn't kill the report.
  Markdown is also pretty-rendered to the terminal via Rich; pass
  `--report path/to/report.md` to also write to disk, or `--json` for
  the combined JSON document.

### Tests

142 total now (+12 since v0.3.0). New: full coverage of every
`profile_module` Markdown helper, the `_serialise_sections` JSON
adapter (handles dataclasses, exceptions, and plain dicts), and the
top-level `_render_markdown` happy and exception paths.

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

[0.5.1]: https://github.com/J4y35/osint-investigator/releases/tag/v0.5.1
[0.5.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.5.0
[0.4.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.4.0
[0.3.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.3.0
[0.2.1]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.1
[0.2.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.2.0
[0.1.0]: https://github.com/J4y35/osint-investigator/releases/tag/v0.1.0
