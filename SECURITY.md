# Security policy

## Reporting a vulnerability

If you've found a security issue in **osint-investigator**, please report it
privately rather than through a public GitHub issue or pull request.

**How to report:**

- Email the maintainer at **phlylow@pm.me** with subject line
  `[osint-investigator security]`.
- Or open a [GitHub Security Advisory](https://github.com/J4y35/osint-investigator/security/advisories/new)
  in this repository — only project maintainers can see those before they're
  published.

Please include:

- A description of the vulnerability and what it would let an attacker do.
- The version (`osint-investigator --version`) where you observed it.
- A minimal reproduction (command line, sample input, expected vs. actual).
- Any disclosure timeline you'd like — happy to coordinate.

I'll acknowledge receipt within 7 days and aim to ship a fix on a timeline
proportional to severity.

## Scope

In scope:

- Code in this repository (`src/osint_investigator/`).
- The bundled package data (`src/osint_investigator/data/`).
- Release artifacts on PyPI.

Out of scope:

- Vulnerabilities in upstream services we query (HIBP, CourtListener, crt.sh,
  rdap.org, ddosecrets.org). Report those to the operators directly.
- Vulnerabilities in transitive dependencies (httpx, dnspython, etc.). Report
  upstream; we'll bump pins promptly once a fix is released.
- Misuse of the tool against subjects without a lawful basis. The README
  documents the legal and ethical constraints — those are operator
  responsibilities, not code defects.

## Supported versions

Only the latest published release on PyPI is supported with security fixes.
Patch releases (e.g. `0.2.x`) for critical issues may be cut against the
most recent minor branch.

## Responsible disclosure

I follow a 90-day coordinated-disclosure window by default. If you need to go
public sooner because the issue is being actively exploited, please tell me in
the initial report and we'll work out a faster timeline.
