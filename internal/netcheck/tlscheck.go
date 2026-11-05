package netcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"email-test-tools/internal/report"
	"email-test-tools/internal/tlsinfo"
)

type TLSRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Mode       string `json:"mode"` // auto | implicit | smtp | imap | pop3
	TimeoutSec int    `json:"timeoutSec"`
}

type TLSResult struct {
	Mode     string          `json:"mode"`
	Info     *tlsinfo.Info   `json:"info,omitempty"`
	Versions map[string]bool `json:"versions"` // which TLS versions the server accepts
}

func autoMode(port int) string {
	switch port {
	case 25, 587, 2525:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	}
	return "implicit"
}

var modeName = map[string]string{
	"implicit": "SSL/TLS from the start", "smtp": "SMTP + STARTTLS",
	"imap": "IMAP + STARTTLS", "pop3": "POP3 + STLS",
}

func CheckTLS(ctx context.Context, req TLSRequest) *report.Report {
	rep := report.New("tls")
	host := cleanHost(req.Host)
	timeout := secs(req.TimeoutSec, 10, 60)
	res := &TLSResult{Versions: map[string]bool{}}
	rep.Data = res
	if host == "" || req.Port <= 0 || req.Port > 65535 {
		rep.Add(&report.Step{ID: "input", Title: "Check your settings", Status: report.Fail, Summary: "Enter a server address and a port (e.g. 465, 587, 993)."})
		rep.Headline = "Nothing to check yet."
		return rep.Finish()
	}
	mode := req.Mode
	if mode == "" || mode == "auto" {
		mode = autoMode(req.Port)
	}
	res.Mode = mode
	addr := net.JoinHostPort(host, strconv.Itoa(req.Port))

	// 1) Main handshake with modern defaults, verification done separately.
	st := rep.Begin("handshake", "Secure connection ("+modeName[mode]+")")
	cs, err := handshake(ctx, rep, addr, host, mode, timeout, 0, 0, true)
	if err != nil {
		st.Detail("%v", err)
		st.Set(report.Fail, "We couldn't set up a secure connection: "+err.Error(),
			"Check the port and the connection type. Ports 465/993/995 use SSL/TLS from the start; 587/25/143/110 use STARTTLS.")
		rep.Finish()
		rep.Headline = "No secure connection to " + addr
		return rep
	}
	info := tlsinfo.FromState(*cs, host)
	res.Info = info
	st.Detail("%s · %s", info.Version, info.CipherSuite)
	if cs.Version < tls.VersionTLS12 {
		st.Set(report.Warn, "Connected, but with outdated encryption ("+info.Version+").", "The server should support TLS 1.2 or 1.3.")
	} else {
		st.Set(report.OK, "Connected securely using "+info.Version+".", "")
	}

	// 2) Certificate.
	leaf := info.Chain[0]
	cst := rep.Begin("cert", "Security certificate")
	cst.Detail("Issued to: %s", leaf.Subject)
	cst.Detail("Covers: %s", strings.Join(leaf.DNSNames, ", "))
	cst.Detail("Issued by: %s", leaf.Issuer)
	cst.Detail("Valid: %s → %s", leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"))
	cst.Detail("Chain length: %d, signature: %s", len(info.Chain), leaf.SigAlgorithm)
	if info.TrustError != "" {
		cst.Detail("Verify error: %s", info.TrustError)
	}
	switch {
	case leaf.DaysLeft < 0:
		cst.Set(report.Fail, fmt.Sprintf("The certificate expired %d day(s) ago.", -leaf.DaysLeft), "Email apps will refuse to connect or show security warnings. The administrator must renew it.")
	case !info.NameMatches:
		cst.Set(report.Fail, fmt.Sprintf("The certificate isn't valid for “%s”.", host),
			"Connect using one of the names the certificate covers (listed in the details), or ask the administrator to issue a certificate for this name.")
	case !info.Trusted:
		cst.Set(report.Fail, "The certificate isn't trusted (self-signed, private CA, or missing intermediate certificate).",
			"Apps will show a security warning. The administrator should install a certificate from a public authority (e.g. Let's Encrypt) including the full chain.")
	case leaf.DaysLeft < 14:
		cst.Set(report.Warn, fmt.Sprintf("Valid, but expires in %d day(s).", leaf.DaysLeft), "Renew it soon to avoid an outage.")
	default:
		cst.Set(report.OK, fmt.Sprintf("Valid and trusted. Expires in %d days.", leaf.DaysLeft), "")
	}

	// 3) Which versions are accepted.
	vst := rep.Begin("versions", "Supported encryption versions")
	versions := []struct {
		v    uint16
		name string
	}{{tls.VersionTLS13, "TLS 1.3"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS10, "TLS 1.0"}}
	for _, v := range versions {
		_, err := handshake(ctx, rep, addr, host, mode, timeout, v.v, v.v, false)
		res.Versions[v.name] = err == nil
		mark := "✗"
		if err == nil {
			mark = "✓"
		}
		vst.Detail("%s %s", mark, v.name)
	}
	switch {
	case res.Versions["TLS 1.0"] || res.Versions["TLS 1.1"]:
		vst.Set(report.Warn, "The server still accepts old, insecure versions (TLS 1.0/1.1).", "These should be turned off on the server. Modern clients won't use them anyway.")
	case !res.Versions["TLS 1.3"]:
		vst.Set(report.Info, "Uses TLS 1.2. Fine, though TLS 1.3 is faster and more secure.", "")
	default:
		vst.Set(report.OK, "Only modern versions are accepted.", "")
	}

	rep.Finish()
	switch rep.Status {
	case report.Fail:
		rep.Headline = "There's a problem with the secure connection to " + addr
	case report.Warn:
		rep.Headline = "The secure connection to " + addr + " works, with warnings."
	default:
		rep.Headline = "The secure connection to " + addr + " is healthy."
	}
	return rep
}

// handshake connects, performs STARTTLS if needed, and runs a TLS handshake.
// Verification is skipped here; tlsinfo verifies the chain separately so
// we can still describe a broken certificate.
func handshake(ctx context.Context, rep *report.Report, addr, host, mode string, timeout time.Duration, minV, maxV uint16, verbose bool) (*tls.ConnectionState, error) {
	logf := func(f string, a ...any) {
		if verbose {
			rep.Infof(f, a...)
		}
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	logf("Connected to %s", addr)

	if mode != "implicit" {
		if err := startTLS(rep, c, mode, verbose); err != nil {
			return nil, err
		}
	}
	cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if minV != 0 {
		cfg.MinVersion, cfg.MaxVersion = minV, maxV
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		if verbose {
			rep.Errf("TLS handshake: %v", err)
		} else {
			rep.Infof("probe %s: not accepted (%v)", tls.VersionName(minV), err)
		}
		return nil, fmt.Errorf("handshake: %w", err)
	}
	cs := tc.ConnectionState()
	if verbose {
		logf("TLS handshake OK: %s %s", tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite))
	} else {
		rep.Infof("probe %s: accepted", tls.VersionName(minV))
	}
	return &cs, nil
}

func startTLS(rep *report.Report, c net.Conn, mode string, verbose bool) error {
	br := bufio.NewReader(c)
	send := func(s string) error {
		if verbose {
			rep.Sent("%s", s)
		}
		_, err := fmt.Fprintf(c, "%s\r\n", s)
		return err
	}
	readLine := func() (string, error) {
		l, err := br.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if verbose && l != "" {
			rep.Recv("%s", l)
		}
		return l, err
	}
	// smtpReply reads a multi-line SMTP reply and returns the last line.
	smtpReply := func() (string, error) {
		for {
			l, err := readLine()
			if err != nil {
				return l, err
			}
			if len(l) < 4 || l[3] != '-' {
				return l, nil
			}
		}
	}
	switch mode {
	case "smtp":
		if l, err := smtpReply(); err != nil || !strings.HasPrefix(l, "2") {
			return fmt.Errorf("server greeting: %q %v", l, err)
		}
		send("EHLO email-test-tools.local")
		if l, err := smtpReply(); err != nil || !strings.HasPrefix(l, "2") {
			return fmt.Errorf("EHLO: %q %v", l, err)
		}
		send("STARTTLS")
		if l, err := smtpReply(); err != nil || !strings.HasPrefix(l, "220") {
			return fmt.Errorf("STARTTLS refused: %q %v", l, err)
		}
	case "imap":
		if l, err := readLine(); err != nil || !strings.HasPrefix(l, "* OK") {
			return fmt.Errorf("IMAP greeting: %q %v", l, err)
		}
		send("a1 STARTTLS")
		for {
			l, err := readLine()
			if err != nil {
				return err
			}
			if strings.HasPrefix(l, "a1 ") {
				if !strings.HasPrefix(l, "a1 OK") {
					return fmt.Errorf("STARTTLS refused: %q", l)
				}
				break
			}
		}
	case "pop3":
		if l, err := readLine(); err != nil || !strings.HasPrefix(l, "+OK") {
			return fmt.Errorf("POP3 greeting: %q %v", l, err)
		}
		send("STLS")
		if l, err := readLine(); err != nil || !strings.HasPrefix(l, "+OK") {
			return fmt.Errorf("STLS refused: %q %v", l, err)
		}
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("server sent unexpected data before TLS")
	}
	return nil
}
