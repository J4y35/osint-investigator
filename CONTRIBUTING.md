# Contributing to osint-investigator

Thanks for considering a contribution. This project is small enough that the rules are short.

## Ground rules

- **Be specific.** PRs that touch one thing land faster than PRs that touch ten.
- **Be defensive.** OSINT data sources change constantly. New scrapers should fail gracefully (per-probe `try/except`, sane defaults) so one broken site doesn't sink a whole run.
- **Respect the targets.** Use the polite-scraping defaults from `config.py` (`request_delay`, identifiable `user_agent`, `http_timeout`). Don't add code that hammers a site or impersonates a real browser to bypass anti-bot measures.
- **No paid or proprietary datasets** in PRs without a discussion in an issue first.

## Local setup

```bash
git clone https://github.com/J4y35/osint-investigator.git
cd osint-investigator
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
playwright install chromium
cp .env.example .env
```

## Before opening a PR

```bash
ruff check src tests
ruff format src tests
mypy src
pytest -q
```

The CI workflow runs the same checks on every push and PR.

## Adding a new command

1. Create `src/osint_investigator/modules/<name>_module.py` exposing a `Typer` instance named `app`.
2. Register it in `cli.py` with `app.add_typer(...)`.
3. Add at least one smoke test in `tests/`.
4. Update `README.md` with usage examples.

## Adding a new scraper to `person`

Mimic `_scrape_cyberbackgroundchecks` in `person_module.py`. Each scraper takes `(first, last, state)` and returns `list[PersonHit]`. Register it in the `SCRAPERS` dict. The orchestrator handles concurrency, JSON, and tables for you.

## Reporting bugs

Please include:

- The command you ran (with the email/username obfuscated if needed).
- The full traceback or stderr output.
- Your Python version (`python --version`) and OS.

## Reporting abuse

If you see this tool being used in a way that violates the ethical-use note in the README — stalking, harassment, doxxing, unauthorised investigation — please open an issue or contact the maintainer. We'll act on it.
