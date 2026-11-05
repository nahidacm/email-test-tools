# Development

## Stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Go 1.25, standard library + `golang.org/x/net/dns/dnsmessage` | `net`, `crypto/tls` and `net/textproto` cover almost everything; `dnsmessage` is used to query name servers directly (SOA). Cross-compiles to one static binary. |
| UI | Plain HTML + JavaScript | No framework or JS build step; ~20 KB of JS. |
| Styling | Tailwind CSS v4 + FlyonUI 2 | Accessible components, light/dark themes. Icons: Tabler via `@iconify/tailwind4`. |
| Packaging | `go:embed`, GoReleaser, nfpm, NSIS | UI ships inside the binary; tagged releases build archives, Linux packages and a Windows installer. |

## Project layout

```
main.go                       flags, listener, browser launch, graceful shutdown
internal/
  report/                     shared result model: Report → Steps + Log
  smtpcheck/                  SMTP client (smtpcheck.go) + plain-language errors (explain.go)
  netcheck/                   ports.go, dns.go, tlscheck.go, and the domain report:
                                domain.go (orchestration, MX, SPF, DMARC, BIMI, DKIM), spf.go (SPF syntax),
                                mailserver.go (PTR, SMTP, STARTTLS, open relay), dnshealth.go (NS/SOA),
                                blacklist.go (DNSBL), web.go (HTTPS)
  tlsinfo/                    certificate / TLS connection facts
  server/                     JSON API + localhost / anti-CSRF guard
web/
  embed.go                    embeds web/static into the binary
  src/input.css               Tailwind + FlyonUI entry point
  static/index.html           all pages (hash-routed: #smtp, #domain, …)
  static/assets/app.js        form handling + generic result renderer
  static/assets/app.css       compiled CSS (committed, so `go build` works without Node)
packaging/
  linux/*.desktop             desktop menu entry for .deb/.rpm/.apk
  windows/installer.nsi       NSIS installer script (+ app.ico)
scripts/install.sh|.ps1       one-line installers
docs/                         user guide, check reference (checks.md), this file, screenshots
.goreleaser.yaml              release build config
.github/workflows/            CI and release pipelines
```

## Running locally

Requirements: Go 1.25+. Node 20+ only if you change HTML classes or styles.

```bash
go run . --no-browser                 # http://127.0.0.1:8587
```

While working on the UI:
```bash
npm install
npm run watch:css                     # terminal 1: recompile CSS on change
go run . --no-browser                 # terminal 2 (restart to pick up HTML/JS changes, which are embedded)
```

Useful `make` targets:

| Target | Does |
|---|---|
| `make build` | Compile CSS and build `bin/email-test-tools` |
| `make run` | Build and start |
| `make test` | `go vet` + `go test` |
| `make release` | Quick cross-compile into `dist/` (no packages; use GoReleaser for that) |

> **Commit the CSS.** After changing classes in `index.html`/`app.js`, run `npm run build:css` and commit `web/static/assets/app.css`. CI fails if it is out of date.

## API

All tools are `POST` endpoints taking and returning JSON. Requests must have `Content-Type: application/json` and come from a loopback `Host` (see `internal/server`).

| Endpoint | Request body |
|---|---|
| `/api/smtp` | `{host, port, security: auto\|starttls\|ssl\|none, username, password, from, fromName, to: [..], subject, body, mode: send\|verify, heloName, timeoutSec, skipVerify}` |
| `/api/domain` | `{domain, selectors: [..], server, checks: [auth\|mail\|dns\|blacklist\|web]}` (empty `checks` = all) |
| `/api/ports` | `{host, ports: [..], timeoutSec}` |
| `/api/dns` | `{name, types: [..], server}` |
| `/api/tls` | `{host, port, mode: auto\|implicit\|smtp\|imap\|pop3, timeoutSec}` |
| `GET /api/info` | version and known port names |

Every tool returns the same `report.Report` shape:

```jsonc
{
  "tool": "smtp",
  "status": "fail",                 // ok | warn | fail | info | skip (worst step wins)
  "headline": "Problem at step: Log in",
  "advice": "The username or password was rejected. …",
  "steps": [{ "id": "auth", "title": "Log in", "status": "fail",
              "summary": "…", "hint": "…", "details": ["…"], "durationMs": 311,
              "category": "mail", "target": "mx1.example.com (192.0.2.1)", // optional
              "moreInfo": "https://…/docs/checks.md#ptr" }],                    // optional
  "log": [{ "ms": 1250, "dir": ">", "text": "AUTH PLAIN [credentials hidden]" }],
  "data": { /* tool-specific */ },
  "startedAt": "…", "durationMs": 1561
}
```

Example:
```bash
curl -s -H 'Content-Type: application/json' -d '{"domain":"example.com"}' http://127.0.0.1:8587/api/domain | jq .headline
```

## Adding a tool

1. **Backend**: write `func Check(ctx context.Context, req Request) *report.Report`:
   ```go
   rep := report.New("mytool")
   st := rep.Begin("step-id", "Human title")
   rep.Sent("COMMAND")            // log helpers: Sent, Recv, Infof, Errf
   st.Detail("raw fact for experts")
   st.Set(report.Fail, "Plain-language summary.", "What the user should do.")
   rep.Finish()
   rep.Headline = "…"
   return rep
   ```
   Write summaries for non-technical people; put codes and raw errors in `Detail`/the log. Never log secrets.
   For a multi-area report, use `rep.BeginIn(category, target, id, title).Info(DocsURL + "anchor")`. The UI then shows summary cards, a problems table and grouped steps automatically. Document new checks in `docs/checks.md`.
2. **API**: register it with `handle("/api/mytool", …)` in `internal/server/server.go`.
3. **UI**: add a `<section data-page="mytool">` containing `<form data-tool="mytool">` and `<div data-result="mytool">` to `index.html`, a menu link, and a collector in `COLLECT` in `app.js`. The generic renderer handles the result. Optionally add a summary block in `renderExtra`.
4. Rebuild the CSS, add tests, update the user guide and CHANGELOG.

## Tests

```bash
go test ./...
```
`internal/smtpcheck` runs the SMTP flow against an in-process fake server (success, wrong password, partial recipient rejection, check-only mode, refusing plaintext passwords, connection refused, validation). `internal/netcheck` tests the SPF and DMARC syntax validators. `internal/server` covers the localhost / cross-origin guard.

## Releasing

1. Update `CHANGELOG.md` and commit.
2. Tag and push:
   ```bash
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```
3. The **Release** workflow then:
   - builds Linux/macOS/Windows binaries for x86_64 and arm64 with GoReleaser,
   - creates `.tar.gz`/`.zip` archives and `.deb`/`.rpm`/`.apk` packages,
   - builds `email-test-tools_<version>_windows_setup.exe` with NSIS,
   - publishes everything with `checksums.txt` to a GitHub release.

Dry run locally (Docker):
```bash
docker run --rm -v "$PWD:/src" -w /src goreleaser/goreleaser:v2.20.0 release --snapshot --clean
```

### Not yet done
- Code signing (Windows Authenticode / macOS notarization). Users see SmartScreen/Gatekeeper prompts; `install.sh` clears the macOS quarantine flag.
- Homebrew tap / Scoop / winget manifests. GoReleaser can generate these once the target repositories exist.
