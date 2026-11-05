# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/nahidacm/email-test-tools/releases/tag/v0.1.0
