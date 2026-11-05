# Email Test Tools

A small app that runs on your own computer and helps you figure out **why email isn't working**. It explains each result in plain language and keeps a full technical log for advanced users.

| Tool | Use it when… |
|---|---|
| **SMTP test** | Your app, website, printer or CMS can't send email. Enter the SMTP settings, and it walks through connect → encrypt → log in → sender → recipients → send, telling you exactly where it breaks and what to do. Includes presets for Gmail, Microsoft 365, Yahoo, Zoho, iCloud, Amazon SES, SendGrid, Mailgun and MailHog/Mailpit. |
| **Domain health** | Email lands in spam, or a domain doesn't receive mail. Checks MX, SPF (including the 10-lookup limit), DKIM, DMARC, MTA-STS and TLS-RPT. |
| **Port check** | "Connection timed out." Shows whether ports 25/465/587/993… are open, closed or silently blocked by a firewall or ISP. |
| **DNS lookup** | Look up A, AAAA, MX, TXT, NS, CNAME and PTR records, optionally through a specific DNS server (1.1.1.1, 8.8.8.8…). |
| **Certificate check** | "Certificate error." Inspects the SSL/TLS certificate (implicit TLS or STARTTLS for SMTP/IMAP/POP3): trust, name match, expiry and accepted TLS versions. |

Every result shows:
- a **headline and advice** in plain language,
- each **step** with ✓ / ⚠ / ✗, what it means, and **what to do**,
- **technical details** per step and a timestamped **protocol log** (copyable, downloadable as JSON). Passwords are never logged. Turn on *Technical details* in the top bar to have these open by default.

## Install & run

**Option 1: download a binary (no dependencies).** Grab the file for your system from the releases page, then run it:

```bash
# Linux / macOS
chmod +x email-test-tools-*
./email-test-tools-linux-amd64
```
On Windows, double-click `email-test-tools-windows-amd64.exe`.

Your browser opens at <http://127.0.0.1:8587>. Press **Ctrl+C** to stop.

**Option 2: Docker**
```bash
docker build -t email-test-tools .
docker run --rm -p 127.0.0.1:8587:8587 email-test-tools
```

**Option 3: from source** (Go 1.25+; Node is only needed if you change the UI styles)
```bash
go run .            # uses the committed, pre-built CSS
make build          # npm install + CSS build + binary in bin/
```

### Options
```
--addr 127.0.0.1:8587   where to listen (default; falls back to a free port if busy)
--no-browser            don't open the browser automatically
--version               print version
```

## Privacy & security
- It only listens on `127.0.0.1` by default, so other computers can't use it.
- Passwords are sent only to the SMTP server you're testing. They're never saved, and form values other than the password are remembered only in your browser.
- The API rejects cross-site requests and foreign `Host` headers (DNS rebinding), so websites you visit can't use the app to probe your network.
- `--addr 0.0.0.0:…` exposes the tools to your network. Anyone who can reach it can make this machine connect to arbitrary hosts. Only do this on a trusted network.

## Development

**Stack:** Go standard library backend (no third-party Go modules) · plain JavaScript · [Tailwind CSS v4](https://tailwindcss.com) + [FlyonUI](https://flyonui.com) · [Tabler icons](https://tabler.io/icons) via Iconify. The UI is embedded into the binary with `go:embed`.

```
main.go                     flags, listener, browser launch
internal/report/            shared result format (steps + log)
internal/smtpcheck/         SMTP client + plain-language error explanations
internal/netcheck/          ports, DNS, domain health, TLS check
internal/tlsinfo/           certificate/TLS facts
internal/server/            JSON API (/api/smtp, /api/domain, /api/ports, /api/dns, /api/tls) + security guard
web/src/input.css           Tailwind/FlyonUI entry
web/static/                 index.html, assets/app.js, compiled assets/app.css
```

```bash
make dev    # terminal 1: rebuild CSS on change
go run . --no-browser   # terminal 2
make test
make release            # cross-compiled binaries in dist/
```

After changing classes in HTML/JS, rebuild the CSS (`npm run build:css`) and commit `web/static/assets/app.css`.

### Adding a tool
1. Write a function `func(ctx, Request) *report.Report` that uses `rep.Begin(...)`/`step.Set(status, summary, hint)` and the `rep.Sent/Recv/Infof/Errf` log helpers.
2. Register it in `internal/server/server.go`.
3. Add a `<section data-page="…">` with a `<form data-tool="…">` in `index.html` and a collector in `COLLECT` in `app.js`. The generic renderer does the rest.

### Ideas / roadmap
- Blacklist (DNSBL) check for sending IPs
- IMAP/POP3 login test
- Email header analyzer (paste headers → hops, delays, SPF/DKIM/DMARC results)
- Built-in catch-all SMTP server for testing apps locally
- Live streaming of the log during long tests (SSE)
