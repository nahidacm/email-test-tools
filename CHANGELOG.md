# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Domain health summary cards now count every blacklist checked (e.g. “20 passed, 1 warning, 6 not checked”) instead of one per server, and show lists that couldn't be queried. The headline and copied text use the same counts.

## [0.2.0] - 2026-11-05

### Added
- **Domain health is now a full report** across five areas, with error/warning/passed counts per area, a “problems to look at” table with the affected host, and steps grouped by area. Choose which areas to run.
  - **Email authentication:** full SPF syntax validation (detects records split into quoted pieces without spaces, unknown terms, bad IPs/prefixes, misplaced `all`); DMARC tag validation; BIMI check.
  - **Mail server:** for each MX IP: reverse DNS (PTR) and forward confirmation, SMTP greeting and response time, STARTTLS and certificate validity, open relay test (nothing is sent).
  - **DNS:** name server count, direct authoritative SOA queries to each name server (timeouts, lame delegation, recursive-only servers), same-subnet detection, serial consistency, SOA value ranges.
  - **Blacklist:** MX IPs against 23 DNS blocklists and the domain against 4 domain blocklists; separates major and minor lists and reports lists that couldn't be checked.
  - **Web server:** HTTPS reachability and certificate, HTTP → HTTPS redirect.
- Every check has a **More info** link to the new [check reference](docs/checks.md).
- **Full-width results**: running a test replaces the form with the result, with **Back to settings** (also cancels a running test) and **Run again**.
- **Show/hide the side menu** on desktop (remembered).
- **Copy** buttons for every issue and for all issues at once.
- **Copy AI prompt**: a ready-made prompt for ChatGPT, Claude or an AI agent with the test context, problems, details and log (no passwords), for the whole result or a single issue.
- README: **Updating** section explaining how to update an existing installation for every install method.

### Changed
- Tool pages show either the form or the result, never squeezed side by side.
- New dependency: `golang.org/x/net/dns/dnsmessage`.

## [0.1.0] - 2026-11-05

First release.

### Added
- **SMTP test**: step-by-step SMTP conversation (DNS → connect → greeting → EHLO → STARTTLS → AUTH PLAIN/LOGIN/CRAM-MD5 → MAIL FROM → RCPT TO → DATA). Supports Auto, STARTTLS, SSL/TLS and no encryption, a “check only, don't send” mode, and presets for Gmail, Microsoft 365, Yahoo, Zoho, iCloud, Amazon SES, SendGrid, Mailgun and MailHog/Mailpit. Explains common failures with provider-specific advice.
- **Domain health**: MX, SPF (with recursive 10-lookup count), DKIM (common or custom selectors, key size), DMARC (policy, reporting, subdomain inheritance), MTA-STS and TLS-RPT.
- **Port check**: open / closed / blocked detection with banner grab and TLS detection; one-click outbound port 25 test.
- **DNS lookup**: A, AAAA, MX, TXT, NS, CNAME and PTR, optionally via a chosen DNS server.
- **Certificate check**: implicit TLS or STARTTLS (SMTP/IMAP/POP3); trust, name match, expiry, chain, cipher and accepted TLS versions.
- Plain-language results with “What to do” hints, per-step technical details, and a timestamped protocol log (copy / JSON download). Passwords are never logged.
- Light and dark themes (FlyonUI).
- Single self-contained binary; localhost-only by default, with DNS-rebinding and cross-site request protection.
- Installers: Windows setup.exe, `.deb`/`.rpm`/`.apk`, one-line install scripts for macOS/Linux and Windows.

[0.2.0]: https://github.com/nahidacm/email-test-tools/releases/tag/v0.2.0
[0.1.0]: https://github.com/nahidacm/email-test-tools/releases/tag/v0.1.0
