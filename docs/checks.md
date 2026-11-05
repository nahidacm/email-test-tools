# Check reference

Every check in the **Domain health** report links here with **More info**. Each section explains what is checked, why it matters, and how to fix a problem.

Most fixes are made at your **DNS provider** (where your domain's DNS records are managed, often the registrar or hosting company). DNS changes usually apply within minutes, but can take up to 48 hours.

**Email authentication:** [SPF](#spf) · [SPF syntax](#spf-syntax) · [DMARC](#dmarc) · [BIMI](#bimi) · [DKIM](#dkim) · [MTA-STS & TLS-RPT](#mta-sts)
**Mail server:** [MX](#mx) · [Reverse DNS (PTR)](#ptr) · [SMTP banner](#smtp-banner) · [STARTTLS](#starttls) · [Open relay](#open-relay)
**DNS:** [Name servers](#ns) · [Name servers answer](#ns-respond) · [Different networks](#ns-subnet) · [Serial numbers](#soa-serial) · [SOA values](#soa-values)
**Blacklist:** [Blacklists](#blacklist)
**Web server:** [Website over HTTPS](#website) · [HTTP → HTTPS redirect](#https-redirect)

---

## Email authentication

<a id="spf"></a>
### SPF: who may send as this domain

An SPF record is a TXT record on your domain that lists the servers allowed to send email using your domain in the sender address. Receivers compare the sending server against it.

```
example.com.  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
```

| Ending | Meaning |
|---|---|
| `-all` | Strict: reject mail from servers not listed. |
| `~all` | Soft fail: accept but treat as suspicious. A good default. |
| `?all` | Neutral: no opinion. Gives little protection. |
| `+all` | Anyone may send. **Never use this.** |

**Rules that commonly break SPF**
- **Only one SPF record per domain.** Two `v=spf1` records make both invalid. Merge them.
- **At most 10 DNS lookups.** Every `include:`, `a`, `mx`, `ptr`, `exists:` and `redirect=` counts, including those nested inside includes. The tool counts them for you. Remove services you no longer use.

<a id="spf-syntax"></a>
### SPF syntax

If the record has a syntax error, receivers treat it as a *permanent error*, as if you had no SPF at all.

**The most common mistake: split pieces without spaces.** DNS panels sometimes store a record as several quoted pieces. DNS glues them together **with nothing in between**:

```
"v=spf1" "include:mxroute.com" "-all"   →   v=spf1include:mxroute.com-all   ✗
"v=spf1 " "include:mxroute.com " "-all" →   v=spf1 include:mxroute.com -all ✓
```

Fix it by entering the whole record as one value, or by putting a space at the end of each piece.

Other errors the tool detects: unknown terms (typos like `inclde:`), `include` without a domain, invalid IP addresses or prefix lengths in `ip4:`/`ip6:`, an IPv6 address in `ip4:`, `all` more than once, and terms after `all` (which are ignored).

<a id="dmarc"></a>
### DMARC: what happens to fake email

DMARC tells receivers what to do with mail that claims to be from your domain but fails SPF and DKIM, and where to send reports. It lives at `_dmarc.yourdomain`:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

| Policy | Effect |
|---|---|
| `p=none` | Monitor only. Nothing is blocked. Start here. |
| `p=quarantine` | Failing mail goes to spam. |
| `p=reject` | Failing mail is refused. The strongest protection. |

**Rollout:** publish `p=none` with a `rua=` address, read the reports for a few weeks until all of your real sending services pass, then move to `quarantine` and finally `reject`.

Since 2024, **Gmail, Yahoo and Microsoft require DMARC** for bulk senders, and missing DMARC hurts deliverability for everyone.

The tool also validates tag values: `p`/`sp` must be none, quarantine or reject; `pct` must be 0–100; `adkim`/`aspf` must be `r` or `s`; `rua`/`ruf` must be `mailto:` addresses.

<a id="bimi"></a>
### BIMI: brand logo in inboxes

BIMI shows your logo next to your messages in supporting inboxes (Gmail, Yahoo, Apple Mail). It's optional and requires:
1. DMARC at **`p=quarantine` or `p=reject`** with `pct=100` (or no pct),
2. a TXT record at `default._bimi.yourdomain`, e.g. `v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem`,
3. a logo in SVG Tiny PS format; Gmail and Apple also require a **mark certificate** (VMC or CMC, the `a=` value).

<a id="dkim"></a>
### DKIM: are messages signed

DKIM adds a digital signature to each message. Receivers verify it with a public key published at `SELECTOR._domainkey.yourdomain`. It proves the message really came from your domain and wasn't altered.

- **Turn it on in your email provider's admin panel** (Google Workspace, Microsoft 365, your mail host, newsletter service…). It gives you the DNS record to add.
- The *selector* is a name chosen by the provider. The tool tries about 35 common ones. If yours isn't found, open a message sent from the domain, view the original/headers, and find `DKIM-Signature: … s=SELECTOR;`. Enter that selector in the form.
- Use **2048-bit** keys. 1024-bit keys are considered weak, and an empty `p=` means the key was revoked.

<a id="mta-sts"></a>
### MTA-STS & TLS-RPT

Optional extra protection for mail **sent to** your domain:
- **MTA-STS** (`_mta-sts.yourdomain` TXT + a policy file at `https://mta-sts.yourdomain/.well-known/mta-sts.txt`) tells other servers they must use encrypted, verified connections when delivering to you.
- **TLS-RPT** (`_smtp._tls.yourdomain` TXT) asks them to send you reports when encryption fails.

---

## Mail server

<a id="mx"></a>
### MX: can this domain receive email

MX records list the servers that receive email for the domain, with a priority (lower number = tried first). Without MX records, nobody can email you. Each MX host must resolve to an IP address. Your email provider gives you the correct values.

A single `.` MX (“null MX”) deliberately declares that the domain accepts no email.

<a id="ptr"></a>
### Reverse DNS (PTR)

The reverse DNS (PTR) record gives an IP address a name, e.g. `203.0.113.10 → mail.example.com`. Many receiving servers distrust or reject mail from IPs without one, or where the name doesn't point back to the same IP (*forward-confirmed reverse DNS*).

**PTR records are controlled by whoever owns the IP address**, not by your domain's DNS. If your email or hosting provider runs the server, ask their support; on your own server, set it in your hosting/VPS control panel or ask the ISP.

<a id="smtp-banner"></a>
### Accepts email (SMTP on port 25)

We connect to each mail server on port 25 (the port other servers use to deliver email), wait for its greeting, and time it.

- **Refused:** the mail service isn't running, so nobody can deliver to you.
- **Timed out:** often *your* network. Most home and cloud providers block outgoing port 25. Try from another network or a server before concluding the mail server is down.
- **Slow greeting (over 3–10 s):** some servers delay on purpose against spam (“tarpitting”), but very slow greetings can make senders give up.

<a id="starttls"></a>
### Encryption (STARTTLS)

Mail servers should offer **STARTTLS** so that email is encrypted between servers. Without it, messages travel in plain text, and Gmail shows a red open-lock icon on such mail.

The certificate should be valid, unexpired, from a trusted authority, and cover the MX host name. Most senders still deliver to servers with a bad certificate, but strict senders (MTA-STS, DANE) won't.

<a id="open-relay"></a>
### Open relay

An *open relay* accepts mail from anyone, to anyone. Spammers find such servers within hours and the server gets blacklisted everywhere.

We test it safely: we pretend to send from `relay-test@example.com` to `relay-test@example.net`, two outside addresses, and check whether the server accepts the recipient. We then cancel. **No message is ever sent.** A secure server refuses with a “relaying denied” error. If yours accepts, restrict relaying to logged-in users and its own domains immediately.

---

## DNS

<a id="ns"></a>
### Name servers (NS)

Name servers answer DNS questions for your domain. If they all fail, your website **and** email stop working. Use **at least two**. DNS providers normally give you two to four. They're set at your domain registrar.

<a id="ns-respond"></a>
### Name servers answer

We ask each name server directly for the domain's SOA record, without recursion, as other resolvers do.

- **No answer / timeout:** “At least one name server failed to respond in a timely manner.” Resolvers retry other servers, so lookups get slower and less reliable.
- **Not authoritative (lame delegation):** the server is listed for your domain but doesn't hold its records, or only answers as a general-purpose resolver. Lookups may fail intermittently. Ask your DNS provider to host the zone authoritatively on every listed server, or remove the server from the list at your registrar.
- **Slow (over 1 s):** delays every lookup for your website and email.
- **“Couldn't test the name servers directly”:** some ISPs, office firewalls and VPNs silently redirect *all* DNS traffic to their own resolver. The tool detects this by sending a query to `192.0.2.1`, a reserved address where no server can exist. If something answers, direct name server tests would only measure your network's resolver, so they're skipped. Run the check from another network (a phone hotspot or a server) to test the name servers themselves. SOA values are still checked.

If several DNS providers serve the domain (for example Route 53 *and* NS1), each has its own SOA record and serial. Serials are compared only between servers of the same provider (same SOA primary).

<a id="ns-subnet"></a>
### Name servers on different networks

If all name servers sit in the same network (same /24 subnet), a single network outage or attack takes them all down. RFC 2182 recommends spreading them across networks and locations. Ask your DNS provider, or add a secondary DNS service.

<a id="soa-serial"></a>
### Name servers are in sync (serial numbers)

Every change to a DNS zone increases its SOA serial number. If name servers report different serials, some still serve old records. That's normal for a few minutes after a change. If it lasts hours, zone transfers between the servers are broken.

<a id="soa-values"></a>
### Zone settings (SOA values)

The SOA record holds timing values for secondary name servers. Recommended ranges (RFC 1912, RIPE-203):

| Value | Meaning | Recommended |
|---|---|---|
| Refresh | How often secondaries check for changes | 1200 – 43200 s (20 min – 12 h) |
| Retry | How soon to retry after a failed check | 120 – 7200 s, and lower than Refresh |
| Expire | How long secondaries keep answering if the primary is unreachable | 1209600 – 2419200 s (2 – 4 weeks) |
| Minimum TTL | How long “does not exist” answers are cached | 300 – 86400 s |

These are usually set by your DNS provider. Values outside the range rarely break anything, but are worth mentioning to them. A too-short Expire, for example, means your domain disappears sooner if the primary server has a long outage.

---

## Blacklist

<a id="blacklist"></a>
### Blacklists (DNSBL)

Blacklists (DNS-based blocklists) record IP addresses and domains seen sending spam. Receivers consult them, and a listing on a **major** list (Spamhaus, SpamCop, Barracuda…) means much of your email is rejected or spam-foldered. Smaller or aggressive lists (e.g. UCEPROTECT levels 2–3, which list whole networks) are used by few receivers and are shown as warnings.

The tool checks each mail server IP against 23 lists and the domain against 4 domain lists.

**If you're listed**
1. **Fix the cause first:** a compromised mailbox or website, malware on a computer, a misconfigured server (open relay), or sending to purchased lists.
2. **Request removal** on the list's website. The **More info** link opens the first list you're on; the technical details list all of them. Most lists remove you automatically after the problem stops.
3. If your email provider runs the server, tell them. They have to request removal.

**“Couldn't be checked”**: some lists refuse lookups made through big public DNS resolvers (8.8.8.8, 1.1.1.1…) or are rate-limited. Choose *Your computer's default* DNS server, or run the check from another network.

---

## Web server

<a id="website"></a>
### Website over HTTPS

Checks that `https://yourdomain` (or `www.` if the bare domain has no address) loads with a valid certificate. Links in your emails usually point to your website, and a broken or “Not secure” site hurts trust and deliverability. If the domain is used only for email, having no website is fine.

<a id="https-redirect"></a>
### HTTP sends visitors to HTTPS

Visitors who type `http://` should be redirected permanently (301) to `https://`. Set this in your web server or hosting control panel (often a “Force HTTPS” switch).
