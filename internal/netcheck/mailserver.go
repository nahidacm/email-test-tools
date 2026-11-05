package netcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
	"github.com/nahidacm/email-test-tools/internal/tlsinfo"
)

// mxTarget is one IP address, shared by one or more MX host names.
type mxTarget struct {
	IP    string
	Hosts []string
}

func (t mxTarget) label() string { return strings.Join(t.Hosts, ", ") + " (" + t.IP + ")" }

// mxTargets groups MX hosts by IPv4 address (first 2 per host, max 6 total).
func mxTargets(mxs []mxHost) []mxTarget {
	byIP := map[string]*mxTarget{}
	var order []string
	for _, m := range mxs {
		n := 0
		for _, ip := range m.IPs {
			if p := net.ParseIP(ip); p == nil || p.To4() == nil || n >= 2 {
				continue
			}
			n++
			t, ok := byIP[ip]
			if !ok {
				if len(order) >= 6 {
					continue
				}
				t = &mxTarget{IP: ip}
				byIP[ip] = t
				order = append(order, ip)
			}
			t.Hosts = append(t.Hosts, m.Host)
		}
	}
	out := make([]mxTarget, 0, len(order))
	for _, ip := range order {
		out = append(out, *byIP[ip])
	}
	return out
}

func checkMailServers(ctx context.Context, rep *report.Report, r *net.Resolver, mxs []mxHost) {
	targets := mxTargets(mxs)
	if len(targets) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t mxTarget) {
			defer wg.Done()
			checkPTR(ctx, rep, r, t)
			checkSMTPServer(ctx, rep, t)
		}(t)
	}
	wg.Wait()
}

func checkPTR(ctx context.Context, rep *report.Report, r *net.Resolver, t mxTarget) {
	st := rep.BeginIn(CatMail, t.label(), "ptr-"+t.IP, "Reverse DNS (PTR)").Info(DocsURL + "ptr")
	rep.Sent("PTR %s", t.IP)
	names, err := r.LookupAddr(ctx, t.IP)
	if err != nil || len(names) == 0 {
		st.Detail("No PTR record for %s", t.IP)
		st.Set(report.Warn, "Reverse DNS Resolution: no PTR record found. This server's IP address has no name, which many receiving servers treat as suspicious.",
			"Only the owner of the IP address can add a PTR record: usually your email or hosting provider. If they run this mail server for you, ask their support.")
		return
	}
	confirmed := false
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		ips, _ := r.LookupHost(ctx, n)
		match := contains(ips, t.IP)
		confirmed = confirmed || match
		mark := "✗ does not point back"
		if match {
			mark = "✓ points back to " + t.IP
		}
		st.Detail("%s → %s (%s)", t.IP, n, mark)
		rep.Recv("PTR %s → %s (%s)", t.IP, n, mark)
	}
	if !confirmed {
		st.Set(report.Warn, fmt.Sprintf("The IP has a name (%s), but that name doesn't point back to the IP.", strings.TrimSuffix(names[0], ".")),
			"Receivers check that the reverse name and forward address match (“forward-confirmed reverse DNS”). Ask the IP owner to fix the PTR or the name's A record.")
		return
	}
	st.Set(report.OK, fmt.Sprintf("The IP has a matching reverse name: %s.", strings.TrimSuffix(names[0], ".")), "")
}

// smtpConn is a minimal logged SMTP client used for server checks.
type smtpConn struct {
	rep  *report.Report
	conn net.Conn
	tp   *textproto.Conn
	tag  string
}

func (c *smtpConn) cmd(line string) {
	c.rep.Sent("[%s] %s", c.tag, line)
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	c.tp.PrintfLine("%s", line)
}

func (c *smtpConn) reply(wait time.Duration) (int, []string, error) {
	c.conn.SetDeadline(time.Now().Add(wait))
	var lines []string
	for {
		l, err := c.tp.ReadLine()
		if err != nil {
			return 0, lines, err
		}
		c.rep.Recv("[%s] %s", c.tag, l)
		if len(l) < 3 {
			return 0, lines, fmt.Errorf("bad reply %q", l)
		}
		code, err := strconv.Atoi(l[:3])
		if err != nil {
			return 0, lines, fmt.Errorf("bad reply %q", l)
		}
		if len(l) > 4 {
			lines = append(lines, l[4:])
		} else {
			lines = append(lines, "")
		}
		if len(l) == 3 || l[3] != '-' {
			return code, lines, nil
		}
	}
}

func (c *smtpConn) ehlo() (map[string]bool, error) {
	c.cmd("EHLO email-test-tools.local")
	code, lines, err := c.reply(15 * time.Second)
	if err != nil {
		return nil, err
	}
	if code != 250 {
		return nil, fmt.Errorf("EHLO rejected: %d %s", code, strings.Join(lines, " "))
	}
	ext := map[string]bool{}
	for _, l := range lines[1:] {
		k, _, _ := strings.Cut(l, " ")
		ext[strings.ToUpper(k)] = true
	}
	return ext, nil
}

func checkSMTPServer(ctx context.Context, rep *report.Report, t mxTarget) {
	host := t.Hosts[0]
	cs := rep.BeginIn(CatMail, t.label(), "smtp-"+t.IP, "Accepts email (SMTP on port 25)").Info(DocsURL + "smtp-banner")
	d := net.Dialer{Timeout: 10 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.IP, "25"))
	skip := func(why string) {
		for _, x := range []struct{ id, title, doc string }{
			{"starttls-", "Encryption (STARTTLS)", "starttls"}, {"relay-", "Open relay test", "open-relay"},
		} {
			rep.BeginIn(CatMail, t.label(), x.id+t.IP, x.title).Info(DocsURL+x.doc).Set(report.Skip, why, "")
		}
	}
	if err != nil {
		cs.Detail("%v", err)
		var ne net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			cs.Set(report.Fail, "The mail server refused the connection on port 25, so other servers can't deliver email to it.",
				"The mail service may be down or misconfigured. Contact your email provider.")
		case errors.As(err, &ne) && ne.Timeout():
			cs.Set(report.Warn, "Couldn't reach the mail server on port 25 from your network.",
				"Most home and cloud internet providers block outgoing port 25, so this may be your network, not the server. Run the check from another network or a server to be sure.")
		default:
			cs.Set(report.Warn, "Couldn't connect to the mail server: "+err.Error(), "")
		}
		skip("Skipped: no connection.")
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	c := &smtpConn{rep: rep, conn: conn, tp: textproto.NewConn(conn), tag: t.IP}
	connectMs := time.Since(start).Milliseconds()
	code, lines, err := c.reply(30 * time.Second)
	greetMs := time.Since(start).Milliseconds()
	cs.Detail("Connected in %dms, greeting after %dms", connectMs, greetMs)
	if err != nil || code != 220 {
		cs.Detail("Greeting: %d %s %v", code, strings.Join(lines, " "), err)
		cs.Set(report.Fail, "The mail server connected but didn't greet properly.", "The server may be overloaded or blocking your IP. Try again later.")
		skip("Skipped: no greeting.")
		return
	}
	banner := strings.Join(lines, " ")
	cs.Detail("Banner: %s", banner)
	switch {
	case greetMs > 10000:
		cs.Set(report.Warn, fmt.Sprintf("The mail server answers, but very slowly (%.1f s).", float64(greetMs)/1000),
			"A slow greeting can make other servers give up. It may be deliberate (anti-spam “tarpitting”) or a sign of overload.")
	case greetMs > 3000:
		cs.Set(report.Warn, fmt.Sprintf("The mail server answers, but slowly (%.1f s).", float64(greetMs)/1000), "")
	default:
		cs.Set(report.OK, fmt.Sprintf("The mail server answers in %dms.", greetMs), "")
	}

	ext, err := c.ehlo()
	if err != nil {
		cs.Detail("EHLO: %v", err)
		skip("Skipped: the server rejected EHLO.")
		return
	}

	// STARTTLS
	ts := rep.BeginIn(CatMail, t.label(), "starttls-"+t.IP, "Encryption (STARTTLS)").Info(DocsURL + "starttls")
	if !ext["STARTTLS"] {
		ts.Set(report.Warn, "The mail server doesn't offer encryption, so email sent to this domain travels in plain text.",
			"Enable STARTTLS with a valid certificate on the mail server. Gmail marks messages from servers without TLS with a red open-lock icon.")
	} else {
		c.cmd("STARTTLS")
		if code, _, err := c.reply(15 * time.Second); err != nil || code != 220 {
			ts.Set(report.Warn, "The server offers STARTTLS but refused to start it.", "")
		} else {
			tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true}) // verified below via tlsinfo
			tc.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tc.HandshakeContext(ctx); err != nil {
				ts.Detail("%v", err)
				ts.Set(report.Warn, "The server offers encryption, but the secure handshake failed.", "")
				rep.BeginIn(CatMail, t.label(), "relay-"+t.IP, "Open relay test").Info(DocsURL+"open-relay").Set(report.Skip, "Skipped: connection lost.", "")
				return
			}
			info := tlsinfo.FromState(tc.ConnectionState(), host)
			ts.Detail("%s, %s", info.Version, info.CipherSuite)
			if len(info.Chain) > 0 {
				lc := info.Chain[0]
				ts.Detail("Certificate: %s (covers %s), issued by %s, %d days left", lc.Subject, strings.Join(lc.DNSNames, ", "), lc.Issuer, lc.DaysLeft)
			}
			if info.TrustError != "" {
				ts.Detail("Verify: %s", info.TrustError)
			}
			switch {
			case len(info.Chain) > 0 && info.Chain[0].DaysLeft < 0:
				ts.Set(report.Warn, "Encryption works, but the certificate has expired.", "Renew the mail server's certificate.")
			case !info.NameMatches:
				ts.Set(report.Warn, fmt.Sprintf("Encryption works, but the certificate isn't valid for %s.", host),
					"Most senders still deliver, but strict ones (MTA-STS, DANE) will refuse. Install a certificate that covers the MX host name.")
			case !info.Trusted:
				ts.Set(report.Warn, "Encryption works, but the certificate isn't from a trusted authority.", "Use a publicly trusted certificate (e.g. Let's Encrypt).")
			default:
				ts.Set(report.OK, fmt.Sprintf("Encrypted with %s and a valid certificate.", info.Version), "")
			}
			conn = tc
			c.conn, c.tp = tc, textproto.NewConn(tc)
			if ext, err = c.ehlo(); err != nil {
				rep.BeginIn(CatMail, t.label(), "relay-"+t.IP, "Open relay test").Info(DocsURL+"open-relay").Set(report.Skip, "Skipped: EHLO after STARTTLS failed.", "")
				return
			}
		}
	}

	// Open relay: will it accept mail from a stranger to a stranger? Nothing is sent.
	rs := rep.BeginIn(CatMail, t.label(), "relay-"+t.IP, "Open relay test").Info(DocsURL + "open-relay")
	c.cmd("MAIL FROM:<relay-test@example.com>")
	code, lines, err = c.reply(20 * time.Second)
	if err == nil && code/100 == 2 {
		c.cmd("RCPT TO:<relay-test@example.net>")
		code, lines, err = c.reply(30 * time.Second)
	}
	reply := strings.Join(lines, " ")
	c.cmd("RSET")
	c.reply(5 * time.Second)
	c.cmd("QUIT")
	c.reply(3 * time.Second)
	rs.Detail("MAIL FROM example.com → RCPT TO example.net: %d %s", code, reply)
	switch {
	case err != nil:
		rs.Set(report.Info, "Couldn't complete the test: "+err.Error(), "")
	case code/100 == 2:
		rs.Set(report.Fail, "OPEN RELAY: the server accepted mail from a stranger for another stranger. Spammers abuse such servers, and it will quickly be blacklisted.",
			"Configure the server to relay only for logged-in users and its own domains. Do this urgently.")
	default:
		rs.Set(report.OK, "Not an open relay: it refuses to forward strangers' mail.", "")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
