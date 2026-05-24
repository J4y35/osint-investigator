# osint-investigator

A modern, modular OSINT command-line tool for private-investigation work on macOS / Linux.

Built with [Typer](https://typer.tiangolo.com/) + [Rich](https://rich.readthedocs.io/) for a
fast, pleasant terminal UX, [Holehe](https://github.com/megadose/holehe) for email-existence
checks, and [Playwright](https://playwright.dev/python/) for JavaScript-heavy people-finder
sites such as cyberbackgroundchecks.com.

[![CI](https://github.com/J4y35/osint-investigator/actions/workflows/ci.yml/badge.svg)](https://github.com/J4y35/osint-investigator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

---

## ⚠️ Ethical and legal use

**This tool is for authorised investigative work only.** Examples of legitimate use:

- Investigating your own accounts and digital footprint.
- Licensed private-investigator casework with a signed engagement.
- Due-diligence research on a counterparty in a transaction you're a party to.
- Missing-persons work in cooperation with family or law enforcement.
- Defensive security research on assets you own or are authorised to test.

**You are personally responsible** for complying with:

- The Computer Fraud and Abuse Act (US) and equivalents in your country.
- GDPR (EU/UK), CCPA (California), PIPEDA (Canada), and other privacy laws.
- Each target site's Terms of Service.
- Any PI licensing requirements in your jurisdiction.
- Stalking, harassment, and anti-doxxing statutes — these apply *even when the data is public*.

**Do not use this tool to:** stalk, harass, dox, blackmail, surveil intimate partners, profile
people on the basis of protected characteristics, or investigate anyone you don't have a lawful
basis to investigate. If you're unsure whether your use is lawful, talk to a lawyer before running
it. Misuse may be a criminal offence.

The author provides this software "as is" and disclaims liability for misuse. See [LICENSE](LICENSE).

## Features

- `email` — Run ~120 Holehe probes against an email and print a Rich table or JSON.
- `person` — Multi-source person lookup. Today: **CourtListener** (free federal court
  records via the v4 REST API) and a Playwright scaffold for **cyberbackgroundchecks**
  (the site is gated by Cloudflare Turnstile — the source reports `blocked` with a
  clear message rather than silently returning zero hits).
- `username` — Check a handle across ~460 sites (Sherlock catalogue bundled into the
  wheel). Filtering via `--site`, `--top`, `--include-nsfw`; concurrency capped via
  `--concurrency`; full catalogue with `--all`.
- `domain` — Investigate a domain across three sections: **RDAP** (via `rdap.org`)
  for registrar/dates/status/nameservers, **DNS** (A/AAAA/MX/NS/TXT/CAA via
  `dnspython`), and **subdomain enumeration** from Certificate Transparency logs
  (via `crt.sh`). Section-selectable with `--section`.
- `breach` — Lookup against Have I Been Pwned + DDoSecrets release index.
- `password` — Check a password against HIBP's PwnedPasswords corpus via
  [k-anonymity](https://en.wikipedia.org/wiki/K-anonymity). Your password
  never leaves your machine.
- `--json` flag on every command for clean piping into `jq`, files, or other tooling.
- `--output FILE` flag on every command to append the JSON result as one
  JSONL record to a case file — accumulate an entire investigation across
  multiple invocations into one file `jq` and `grep` can read directly.
- Polite scraping by default (configurable delay, identifiable User-Agent).
- Typed throughout, `mypy --strict` clean, formatted with `ruff`.

## Project layout

```
osint-investigator/
├── pyproject.toml
├── README.md
├── .env.example
├── src/osint_investigator/
│   ├── __init__.py
│   ├── cli.py              # Typer root app
│   ├── config.py           # pydantic-settings, .env loader
│   ├── utils.py            # shared helpers (console, JSON printer, polite sleep)
│   ├── data/               # bundled package data (Sherlock catalogue snapshot)
│   └── modules/
│       ├── __init__.py
│       ├── email_module.py     # Holehe orchestrator
│       ├── person_module.py    # CourtListener + Playwright (Cloudflare-aware)
│       ├── username_module.py  # Sherlock-backed handle probe
│       ├── sherlock_sites.py   # Sherlock data.json loader + site selection
│       ├── domain_module.py    # RDAP + DNS + crt.sh
│       ├── breach_module.py    # HIBP + DDoSecrets
│       └── password_module.py  # HIBP PwnedPasswords k-anonymity check
└── tests/                  # pytest suite (offline; fixtures under tests/fixtures/)
```

## Install

```bash
# Stable release from PyPI
pip install osint-investigator
playwright install chromium  # only needed if you use the `person` cyberbackgroundchecks source

# Or the latest from main
pip install "git+https://github.com/J4y35/osint-investigator.git"
```

Then (optional) drop a `.env` next to your shell with an HIBP API key so the
`breach` command can talk to Have I Been Pwned:

```bash
echo 'HIBP_API_KEY=your-key-here' > .env
```

## Development quickstart (macOS / Linux)

```bash
# 1. Clone the project
git clone https://github.com/J4y35/osint-investigator.git
cd osint-investigator

# 2. Create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode + Playwright browsers
pip install --upgrade pip
pip install -e ".[dev]"
playwright install chromium

# 4. Configure
cp .env.example .env
# then edit .env to add HIBP_API_KEY etc. (all optional)

# 5. Verify
osint-investigator --help
pytest -q
```

## Commands

### `email`

Check ~120 sites with Holehe.

```bash
osint-investigator email --email someone@gmail.com
osint-investigator email --email someone@gmail.com --json > result.json
osint-investigator email --email someone@gmail.com --only-found
```

### `person`

Search people-finder sites. Currently wired to cyberbackgroundchecks.com.

```bash
osint-investigator person --first Jane --last Doe --state CA
```

### `username`

Check whether a handle is registered.

```bash
osint-investigator username --username johnsmith
```

### `breach`

Lookup breach corpora (HIBP requires `HIBP_API_KEY` in `.env`).

```bash
osint-investigator breach --query someone@gmail.com
```

## Configuration

All configuration lives in `.env`. See [`.env.example`](.env.example) for the full set.

| Variable | Purpose | Default |
| --- | --- | --- |
| `HIBP_API_KEY` | Have I Been Pwned API key | _(unset → HIBP skipped)_ |
| `HUNTER_API_KEY` | Hunter.io API key | _(unset)_ |
| `INTELX_API_KEY` | IntelX API key | _(unset)_ |
| `OSINT_USER_AGENT` | UA sent on every request | `osint-investigator/0.1 …` |
| `OSINT_REQUEST_DELAY` | Politeness delay (seconds) | `1.5` |
| `OSINT_HTTP_TIMEOUT` | Per-request timeout (seconds) | `20` |
| `OSINT_PLAYWRIGHT_HEADLESS` | Headless browser? | `true` |
| `OSINT_OUTPUT_DIR` | Where to write JSON exports | `./output` |

## Extending

Each subcommand is a self-contained module under `src/osint_investigator/modules/`. To add
a new command:

1. Create `modules/<name>_module.py` exposing a `Typer` instance named `app`.
2. Register it in `cli.py` with `app.add_typer(...)`.
3. Re-install (`pip install -e .`) to pick up the entry point — or just rerun.

For people-finder scrapers, mimic `_scrape_cyberbackgroundchecks` in `person_module.py` and
register the new coroutine in the `SCRAPERS` dict.

## Development

```bash
ruff check src tests
ruff format src tests
mypy src
pytest
```

## License

MIT. See `pyproject.toml` for author info.
