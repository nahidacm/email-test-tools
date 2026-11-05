// Package smtpcheck runs a step-by-step SMTP conversation and explains
// every stage in plain language, while recording the raw transcript.
package smtpcheck

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
	"github.com/nahidacm/email-test-tools/internal/tlsinfo"
)

const (
	SecAuto     = "auto"     // 465 → SSL/TLS, otherwise STARTTLS when offered
	SecSSL      = "ssl"      // implicit TLS from the first byte
	SecStartTLS = "starttls" // plain connect, then upgrade (required)
	SecNone     = "none"     // never encrypt

	ModeSend   = "send"   // really deliver a test message
	ModeVerify = "verify" // log in + check recipients, then cancel
)

type Request struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Security   string   `json:"security"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	From       string   `json:"from"`
	FromName   string   `json:"fromName"`
	To         []string `json:"to"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	Mode       string   `json:"mode"`
	HeloName   string   `json:"heloName"`
	SkipVerify bool     `json:"skipVerify"`
	TimeoutSec int      `json:"timeoutSec"`
}

// Result is the tool-specific data attached to the report.
type Result struct {
	Server         string            `json:"server"`
	Security       string            `json:"security"`
	Encrypted      bool              `json:"encrypted"`
	Banner         string            `json:"banner,omitempty"`
	Extensions     map[string]string `json:"extensions,omitempty"`
	AuthMechanisms []string          `json:"authMechanisms,omitempty"`
	AuthUsed       string            `json:"authUsed,omitempty"`
	TLS            *tlsinfo.Info     `json:"tls,omitempty"`
	Accepted       []string          `json:"accepted"`
	Rejected       []string          `json:"rejected"`
	QueueReply     string            `json:"queueReply,omitempty"`
	MessageID      string            `json:"messageId,omitempty"`
	Sent           bool              `json:"sent"`
}

type session struct {
	req       Request
	rep       *report.Report
	res       *Result
	conn      net.Conn
	tp        *textproto.Conn
	timeout   time.Duration
	ext       map[string]string
	encrypted bool
	provider  provider
}

// smtpError is a negative server reply.
type smtpError struct {
	Code     int
	Enhanced string // e.g. 5.7.8
	Msg      string
}

func (e *smtpError) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Msg) }

func Run(ctx context.Context, req Request) *report.Report {
	rep := report.New("smtp")
	res := &Result{Accepted: []string{}, Rejected: []string{}}
	rep.Data = res

	s := &session{req: req, rep: rep, res: res}
	s.run(ctx)
	if s.conn != nil {
		s.conn.Close()
	}
	rep.Finish()
	s.headline()
	return rep
}

func (s *session) run(ctx context.Context) {
	if !s.validate() {
		return
	}
	s.provider = detectProvider(s.req.Host)
	s.res.Server = net.JoinHostPort(s.req.Host, strconv.Itoa(s.req.Port))

	ips, ok := s.resolve(ctx)
	if !ok {
		return
	}
	if !s.connect(ctx, ips) {
		return
	}
	// Abort blocking reads if the browser goes away.
	stop := context.AfterFunc(ctx, func() { s.conn.Close() })
	defer stop()

	if !s.greeting() || !s.hello() {
		return
	}
	if !s.startTLS() {
		return
	}
	if !s.auth() {
		return
	}
	if !s.envelope() {
		return
	}
	s.data()
	s.quit()
}

// ---------------------------------------------------------------- validation

func (s *session) validate() bool {
	st := s.rep.Begin("input", "Check your settings")
	r := &s.req
	r.Host = strings.TrimSpace(r.Host)
	r.Username = strings.TrimSpace(r.Username)
	r.From = strings.TrimSpace(r.From)
	r.Security = strings.ToLower(strings.TrimSpace(r.Security))
	if r.Security == "" {
		r.Security = SecAuto
	}
	if r.Mode != ModeVerify {
		r.Mode = ModeSend
	}
	if r.TimeoutSec <= 0 || r.TimeoutSec > 120 {
		r.TimeoutSec = 15
	}
	s.timeout = time.Duration(r.TimeoutSec) * time.Second

	var problems []string
	if r.Host == "" {
		problems = append(problems, "The SMTP server address is empty.")
	} else if strings.Contains(r.Host, "://") || strings.ContainsAny(r.Host, " /@") {
		problems = append(problems, fmt.Sprintf("“%s” doesn't look like a server address. Use just the name, e.g. smtp.example.com (no http://, no slashes, no email address).", r.Host))
	}
	if r.Port <= 0 || r.Port > 65535 {
		problems = append(problems, "The port must be a number between 1 and 65535 (usually 587, 465 or 25).")
	}
	switch r.Security {
	case SecAuto, SecSSL, SecStartTLS, SecNone:
	default:
		problems = append(problems, "Unknown security option: "+r.Security)
	}
	if r.From == "" {
		problems = append(problems, "The sender (From) address is empty.")
	} else if _, err := mail.ParseAddress(r.From); err != nil {
		problems = append(problems, fmt.Sprintf("The sender address “%s” isn't a valid email address.", r.From))
	}
	var to []string
	for _, raw := range r.To {
		for _, part := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == ';' || c == '\n' || c == ' ' }) {
			if a, err := mail.ParseAddress(part); err != nil {
				problems = append(problems, fmt.Sprintf("The recipient “%s” isn't a valid email address.", part))
			} else {
				to = append(to, a.Address)
			}
		}
	}
	r.To = to
	if len(to) == 0 {
		problems = append(problems, "Add at least one recipient email address.")
	}
	if r.Password != "" && r.Username == "" {
		problems = append(problems, "A password was entered but the username is empty.")
	}
	if len(problems) > 0 {
		st.Details = problems
		st.Set(report.Fail, "Some settings need fixing before we can test.", strings.Join(problems, " "))
		return false
	}

	// Resolve "auto" so the rest of the run knows what it is doing.
	if r.Security == SecAuto {
		if r.Port == 465 {
			r.Security = SecSSL
			st.Detail("Security “Auto”: port 465 → SSL/TLS from the start")
		} else {
			st.Detail("Security “Auto”: will upgrade with STARTTLS if the server offers it")
		}
	}
	s.res.Security = r.Security
	st.Detail("Server %s:%d, security=%s, mode=%s, timeout=%s", r.Host, r.Port, r.Security, r.Mode, s.timeout)

	var warns []string
	if r.Port == 465 && r.Security == SecStartTLS {
		warns = append(warns, "Port 465 normally uses SSL/TLS, not STARTTLS. If the test hangs at “server greeting”, switch Security to SSL/TLS.")
	}
	if (r.Port == 587 || r.Port == 25) && r.Security == SecSSL {
		warns = append(warns, fmt.Sprintf("Port %d normally uses STARTTLS, not SSL/TLS. If the secure connection fails, switch Security to STARTTLS.", r.Port))
	}
	if r.Security == SecNone && r.Password != "" {
		warns = append(warns, "Security is set to None, so your password will travel unencrypted. Only do this on a trusted local network.")
	}
	if r.SkipVerify {
		warns = append(warns, "Certificate checking is turned off. Fine for testing, but real apps should keep it on.")
	}
	if len(warns) > 0 {
		st.Set(report.Warn, "Settings look usable, with some things to note.", strings.Join(warns, " "))
	} else {
		st.Set(report.OK, "Settings look complete.", "")
	}
	return true
}

// ---------------------------------------------------------------- network

func (s *session) resolve(ctx context.Context) ([]net.IP, bool) {
	st := s.rep.Begin("dns", "Find the server")
	if ip := net.ParseIP(s.req.Host); ip != nil {
		st.Detail("Host is an IP address: %s", ip)
		st.Set(report.OK, "Server address is an IP, no lookup needed.", "")
		return []net.IP{ip}, true
	}
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	s.rep.Infof("Looking up %s", s.req.Host)
	addrs, err := net.DefaultResolver.LookupIPAddr(cctx, s.req.Host)
	if err != nil {
		s.rep.Errf("DNS lookup failed: %v", err)
		st.Detail("%v", err)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			st.Set(report.Fail, fmt.Sprintf("No server called “%s” exists.", s.req.Host),
				"Check the spelling of the server address. Your email provider's help pages list the exact name (for example smtp.gmail.com or smtp.office365.com).")
		} else {
			st.Set(report.Fail, "We couldn't look up the server address.",
				"Your internet connection or DNS service may be down. Check that other websites load, then try again.")
		}
		return nil, false
	}
	var ips []net.IP
	for _, a := range addrs {
		ips = append(ips, a.IP)
		st.Detail("%s → %s", s.req.Host, a.IP)
	}
	s.rep.Infof("Resolved to %v", ips)
	st.Set(report.OK, fmt.Sprintf("Found the server (%d address%s).", len(ips), plural(len(ips), "es")), "")
	return ips, true
}

func (s *session) connect(ctx context.Context, ips []net.IP) bool {
	st := s.rep.Begin("connect", fmt.Sprintf("Connect to port %d", s.req.Port))
	d := net.Dialer{Timeout: s.timeout}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(s.req.Port))
		s.rep.Infof("Connecting to %s", addr)
		t := report.StartTimer()
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			s.rep.Errf("%s: %v", addr, err)
			st.Detail("%s: %v", addr, err)
			lastErr = err
			continue
		}
		s.rep.Infof("Connected to %s from %s in %dms", addr, c.LocalAddr(), t.Ms())
		st.Detail("Connected to %s in %dms (local %s)", addr, t.Ms(), c.LocalAddr())
		s.conn = c
		break
	}
	if s.conn == nil {
		sum, hint := explainNetErr(lastErr, s.req.Port)
		st.Set(report.Fail, sum, hint)
		return false
	}

	if s.req.Security == SecSSL {
		if !s.handshake(st, "Secure (SSL/TLS) connection") {
			return false
		}
		st.Set(report.OK, "Connected and encrypted the connection (SSL/TLS).", "")
		return true
	}
	st.Set(report.OK, "Connected to the server.", "")
	s.tp = textproto.NewConn(s.conn)
	return true
}

func (s *session) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.req.Host, InsecureSkipVerify: s.req.SkipVerify, MinVersion: tls.VersionTLS10}
}

// handshake wraps s.conn in TLS. Shared by implicit TLS and STARTTLS.
func (s *session) handshake(st *report.Step, what string) bool {
	s.rep.Infof("Starting TLS handshake (SNI %s, verify=%v)", s.req.Host, !s.req.SkipVerify)
	tc := tls.Client(s.conn, s.tlsConfig())
	tc.SetDeadline(time.Now().Add(s.timeout))
	if err := tc.Handshake(); err != nil {
		s.rep.Errf("TLS handshake failed: %v", err)
		st.Detail("TLS error: %v", err)
		sum, hint := explainTLSErr(err, s.req)
		st.Set(report.Fail, what+" failed: "+sum, hint)
		return false
	}
	tc.SetDeadline(time.Time{})
	info := tlsinfo.FromState(tc.ConnectionState(), s.req.Host)
	s.res.TLS = info
	s.rep.Infof("TLS established: %s, %s", info.Version, info.CipherSuite)
	st.Detail("%s, cipher %s", info.Version, info.CipherSuite)
	if len(info.Chain) > 0 {
		c := info.Chain[0]
		st.Detail("Certificate for %s, issued by %s, valid until %s (%d days left)", c.Subject, c.Issuer, c.NotAfter.Format("2006-01-02"), c.DaysLeft)
	}
	s.conn = tc
	s.tp = textproto.NewConn(tc)
	s.encrypted = true
	s.res.Encrypted = true
	return true
}

// ---------------------------------------------------------------- SMTP I/O

func (s *session) cmd(redacted string, format string, a ...any) error {
	line := fmt.Sprintf(format, a...)
	if redacted != "" {
		s.rep.Sent("%s", redacted)
	} else {
		s.rep.Sent("%s", line)
	}
	s.conn.SetDeadline(time.Now().Add(s.timeout))
	return s.tp.PrintfLine("%s", line)
}

// read reads one (possibly multi-line) reply.
func (s *session) read(wait time.Duration) (int, []string, error) {
	s.conn.SetDeadline(time.Now().Add(wait))
	var lines []string
	for {
		line, err := s.tp.ReadLine()
		if err != nil {
			s.rep.Errf("read: %v", err)
			return 0, lines, err
		}
		s.rep.Recv("%s", line)
		if len(line) < 3 {
			return 0, lines, fmt.Errorf("unexpected reply %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, lines, fmt.Errorf("unexpected reply %q", line)
		}
		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		lines = append(lines, msg)
		if len(line) == 3 || line[3] != '-' {
			return code, lines, nil
		}
	}
}

// expect sends nothing; it reads a reply and turns non-matching codes into smtpError.
func (s *session) expect(wait time.Duration, okPrefix int) (int, string, error) {
	code, lines, err := s.read(wait)
	msg := strings.Join(lines, " ")
	if err != nil {
		return code, msg, err
	}
	if code/100 != okPrefix {
		return code, msg, newSMTPError(code, msg)
	}
	return code, msg, nil
}

func (s *session) do(redacted string, okPrefix int, format string, a ...any) (int, string, error) {
	if err := s.cmd(redacted, format, a...); err != nil {
		return 0, "", err
	}
	return s.expect(s.timeout, okPrefix)
}

func newSMTPError(code int, msg string) *smtpError {
	e := &smtpError{Code: code, Msg: msg}
	// Enhanced status code, e.g. "5.7.8 Authentication failed"
	if f := strings.Fields(msg); len(f) > 0 && len(f[0]) >= 5 && f[0][1] == '.' && (f[0][0] >= '2' && f[0][0] <= '5') {
		e.Enhanced = f[0]
	}
	return e
}

// ---------------------------------------------------------------- stages

func (s *session) greeting() bool {
	st := s.rep.Begin("greeting", "Server greeting")
	code, msg, err := s.expect(s.timeout, 2)
	if err != nil {
		st.Detail("%v", err)
		var se *smtpError
		switch {
		case errors.As(err, &se):
			st.Set(report.Fail, "The server answered but refused the connection: "+msg,
				"The server may be busy, or may be blocking your IP address. Wait a few minutes and try again; if it keeps happening, ask your email provider whether your IP is blocked.")
		case isTimeout(err) && !s.encrypted && s.req.Port == 465:
			st.Set(report.Fail, "The server stayed silent.",
				"Port 465 expects an encrypted connection from the very first moment. Change Security to “SSL/TLS” and try again.")
		case isTimeout(err):
			st.Set(report.Fail, "The server accepted the connection but never said hello.",
				"This usually means the security setting doesn't match the port. Try SSL/TLS for port 465 and STARTTLS for 587/25. A firewall or antivirus that inspects mail traffic can also cause this.")
		default:
			st.Set(report.Fail, "The connection dropped before the server said hello.",
				"The server may be rejecting connections from your network. Try again later or from another network.")
		}
		return false
	}
	_ = code
	s.res.Banner = msg
	st.Detail("Banner: %s", msg)
	st.Set(report.OK, "The server is an email server and is ready to talk.", "")
	return true
}

func (s *session) heloName() string {
	if s.req.HeloName != "" {
		return s.req.HeloName
	}
	// An address literal is always valid and avoids sending a bogus hostname.
	if ta, ok := s.conn.LocalAddr().(*net.TCPAddr); ok {
		if ta.IP.To4() != nil {
			return "[" + ta.IP.String() + "]"
		}
		return "[IPv6:" + ta.IP.String() + "]"
	}
	return "localhost"
}

func (s *session) ehlo() error {
	if err := s.cmd("", "EHLO %s", s.heloName()); err != nil {
		return err
	}
	code, lines, err := s.read(s.timeout)
	if err != nil {
		return err
	}
	if code != 250 {
		// Very old servers only know HELO.
		s.rep.Infof("EHLO rejected, falling back to HELO")
		if _, _, err := s.do("", 2, "HELO %s", s.heloName()); err != nil {
			return err
		}
		s.ext = map[string]string{}
		return nil
	}
	s.ext = map[string]string{}
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, " ")
		s.ext[strings.ToUpper(k)] = v
	}
	s.res.Extensions = s.ext
	s.res.AuthMechanisms = strings.Fields(strings.ToUpper(s.ext["AUTH"]))
	return nil
}

func (s *session) hello() bool {
	st := s.rep.Begin("ehlo", "Introduce ourselves (EHLO)")
	if err := s.ehlo(); err != nil {
		st.Detail("%v", err)
		st.Set(report.Fail, "The server didn't accept our introduction.",
			"Some servers reject unknown client names. You can set a custom “HELO name” (for example your domain) under Advanced options.")
		return false
	}
	var feats []string
	for k, v := range s.ext {
		feats = append(feats, strings.TrimSpace(k+" "+v))
	}
	sort.Strings(feats)
	st.Details = append(st.Details, feats...)
	st.Set(report.OK, fmt.Sprintf("The server listed %d supported features.", len(s.ext)), "")
	return true
}

func (s *session) startTLS() bool {
	if s.encrypted {
		return true
	}
	_, offered := s.ext["STARTTLS"]
	st := s.rep.Begin("starttls", "Encrypt the connection (STARTTLS)")
	switch s.req.Security {
	case SecNone:
		st.Set(report.Warn, "Skipped: you chose no encryption.",
			"Without encryption, your password and email content can be read by anyone on the network path. Use STARTTLS or SSL/TLS whenever the server supports it.")
		return true
	case SecAuto:
		if !offered {
			st.Set(report.Warn, "The server doesn't offer encryption on this port.",
				"Your messages and password would travel unencrypted. Check whether your provider supports port 587 (STARTTLS) or 465 (SSL/TLS).")
			return true
		}
	case SecStartTLS:
		if !offered {
			hint := "Check the port: STARTTLS is normally used on 587 or 25."
			if s.req.Port == 465 {
				hint = "Port 465 uses SSL/TLS instead. Change Security to “SSL/TLS”."
			}
			st.Set(report.Fail, "You asked for STARTTLS, but the server doesn't offer it.", hint)
			return false
		}
	}
	if _, _, err := s.do("", 2, "STARTTLS"); err != nil {
		st.Detail("%v", err)
		st.Set(report.Fail, "The server refused to start encryption.", "The server advertised STARTTLS but then rejected it. This is a server-side problem; contact your email provider.")
		return false
	}
	if !s.handshake(st, "Encryption") {
		return false
	}
	// Capabilities must be re-read after upgrading (RFC 3207).
	if err := s.ehlo(); err != nil {
		st.Detail("EHLO after STARTTLS failed: %v", err)
		st.Set(report.Fail, "The server stopped responding after encryption started.", "")
		return false
	}
	st.Set(report.OK, "The connection is now encrypted.", "")
	return true
}

func (s *session) auth() bool {
	if s.req.Username == "" {
		st := s.rep.Begin("auth", "Log in")
		if _, needs := s.ext["AUTH"]; needs {
			st.Set(report.Info, "Skipped: no username given.",
				"The server supports logging in. Most servers require it before they'll send email to outside addresses. If the next steps fail with “relay denied”, add your username and password.")
		} else {
			st.Set(report.Info, "Skipped: no username given and the server doesn't ask for one.", "")
		}
		return true
	}
	st := s.rep.Begin("auth", "Log in")
	if !s.encrypted && s.req.Security != SecNone {
		st.Set(report.Fail, "We stopped before sending your password, because the connection isn't encrypted.",
			"Use a port and security mode that supports encryption (587 + STARTTLS or 465 + SSL/TLS). If you really want to log in without encryption, set Security to “None”.")
		return false
	}
	mechs := s.res.AuthMechanisms
	if len(mechs) == 0 {
		hint := "This server or port may not accept logins. Try port 587 instead, or leave the username empty if this is an internal relay."
		if !s.encrypted {
			hint = "Many servers only offer login after encryption is turned on. Try STARTTLS or SSL/TLS."
		}
		st.Set(report.Fail, "The server doesn't offer any way to log in here.", hint)
		return false
	}
	st.Detail("Server offers: %s", strings.Join(mechs, ", "))

	var err error
	switch {
	case has(mechs, "PLAIN"):
		s.res.AuthUsed = "PLAIN"
		cred := base64.StdEncoding.EncodeToString([]byte("\x00" + s.req.Username + "\x00" + s.req.Password))
		_, _, err = s.do("AUTH PLAIN [credentials hidden]", 2, "AUTH PLAIN %s", cred)
	case has(mechs, "LOGIN"):
		s.res.AuthUsed = "LOGIN"
		err = s.authLogin()
	case has(mechs, "CRAM-MD5"):
		s.res.AuthUsed = "CRAM-MD5"
		err = s.authCRAM()
	default:
		hint := "This tool supports PLAIN, LOGIN and CRAM-MD5."
		if has(mechs, "XOAUTH2") || has(mechs, "OAUTHBEARER") {
			hint = "This server only accepts OAuth sign-in (used by Google/Microsoft accounts), not a password. Use an app password if the provider offers one, or a different SMTP service."
		}
		st.Set(report.Fail, "The server only offers login methods we don't support ("+strings.Join(mechs, ", ")+").", hint)
		return false
	}
	st.Detail("Method used: %s", s.res.AuthUsed)
	if err != nil {
		st.Detail("%v", err)
		sum, hint := explainSMTP(err, phaseAuth, s.provider)
		st.Set(report.Fail, sum, hint)
		return false
	}
	st.Set(report.OK, fmt.Sprintf("Logged in as %s.", s.req.Username), "")
	return true
}

func (s *session) authLogin() error {
	if _, _, err := s.do("", 3, "AUTH LOGIN"); err != nil {
		return err
	}
	if _, _, err := s.do("[username, base64]", 3, "%s", base64.StdEncoding.EncodeToString([]byte(s.req.Username))); err != nil {
		return err
	}
	_, _, err := s.do("[password hidden]", 2, "%s", base64.StdEncoding.EncodeToString([]byte(s.req.Password)))
	return err
}

func (s *session) authCRAM() error {
	if err := s.cmd("", "AUTH CRAM-MD5"); err != nil {
		return err
	}
	code, lines, err := s.read(s.timeout)
	if err != nil {
		return err
	}
	if code != 334 || len(lines) == 0 {
		return newSMTPError(code, strings.Join(lines, " "))
	}
	challenge, err := base64.StdEncoding.DecodeString(lines[0])
	if err != nil {
		return fmt.Errorf("bad CRAM-MD5 challenge: %w", err)
	}
	m := hmac.New(md5.New, []byte(s.req.Password))
	m.Write(challenge)
	resp := base64.StdEncoding.EncodeToString([]byte(s.req.Username + " " + hex.EncodeToString(m.Sum(nil))))
	_, _, err = s.do("[CRAM-MD5 response hidden]", 2, "%s", resp)
	return err
}

func (s *session) envelope() bool {
	st := s.rep.Begin("from", "Sender address (MAIL FROM)")
	from, _ := mail.ParseAddress(s.req.From)
	if _, _, err := s.do("", 2, "MAIL FROM:<%s>", from.Address); err != nil {
		st.Detail("%v", err)
		sum, hint := explainSMTP(err, phaseFrom, s.provider)
		st.Set(report.Fail, sum, hint)
		return false
	}
	st.Set(report.OK, fmt.Sprintf("The server accepts %s as the sender.", from.Address), "")

	rst := s.rep.Begin("rcpt", "Recipients (RCPT TO)")
	var firstErr error
	for _, to := range s.req.To {
		_, msg, err := s.do("", 2, "RCPT TO:<%s>", to)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.res.Rejected = append(s.res.Rejected, to)
			rst.Detail("✗ %s — %v", to, err)
			if !isSMTPError(err) {
				break // connection problem, no point continuing
			}
			continue
		}
		s.res.Accepted = append(s.res.Accepted, to)
		rst.Detail("✓ %s — %s", to, msg)
	}
	switch {
	case len(s.res.Rejected) == 0:
		rst.Set(report.OK, fmt.Sprintf("All %d recipient%s accepted.", len(s.res.Accepted), plural(len(s.res.Accepted), "s")), "")
	case len(s.res.Accepted) == 0:
		sum, hint := explainSMTP(firstErr, phaseRcpt, s.provider)
		rst.Set(report.Fail, "No recipients were accepted. "+sum, hint)
		return false
	default:
		sum, hint := explainSMTP(firstErr, phaseRcpt, s.provider)
		rst.Set(report.Warn, fmt.Sprintf("%d accepted, %d rejected (%s). %s", len(s.res.Accepted), len(s.res.Rejected), strings.Join(s.res.Rejected, ", "), sum), hint)
	}
	return true
}

func (s *session) data() {
	st := s.rep.Begin("data", "Send the message")
	if s.req.Mode == ModeVerify {
		s.do("", 2, "RSET")
		st.Set(report.Skip, "Not sent: you chose “check only”. Everything up to sending worked.", "")
		return
	}
	if _, _, err := s.do("", 3, "DATA"); err != nil {
		st.Detail("%v", err)
		sum, hint := explainSMTP(err, phaseData, s.provider)
		st.Set(report.Fail, sum, hint)
		return
	}
	msg, msgID := s.buildMessage()
	s.res.MessageID = msgID
	headers, _, _ := bytes.Cut(msg, []byte("\r\n\r\n"))
	for _, h := range strings.Split(string(headers), "\r\n") {
		s.rep.Sent("%s", h)
	}
	s.rep.Sent("[message body, %d bytes total]", len(msg))
	s.rep.Sent(".")

	s.conn.SetDeadline(time.Now().Add(s.timeout))
	w := s.tp.DotWriter()
	_, err := w.Write(msg)
	if err == nil {
		err = w.Close()
	}
	var reply string
	if err == nil {
		// Servers may scan content before answering, so allow extra time.
		_, reply, err = s.expect(s.timeout*3, 2)
	}
	if err != nil {
		st.Detail("%v", err)
		sum, hint := explainSMTP(err, phaseData, s.provider)
		st.Set(report.Fail, sum, hint)
		return
	}
	s.res.QueueReply = reply
	s.res.Sent = true
	st.Detail("Server reply: %s", reply)
	st.Detail("Message-ID: %s", msgID)
	st.Set(report.OK, fmt.Sprintf("The server accepted the message for delivery to %d recipient%s.", len(s.res.Accepted), plural(len(s.res.Accepted), "s")),
		"Check the inbox, and the spam folder, of each recipient. If it doesn't arrive within a few minutes, the receiving side may be filtering it: use the Domain Health tool to check SPF/DKIM/DMARC for the sender's domain.")
}

func (s *session) quit() {
	s.cmd("", "QUIT")
	s.read(3 * time.Second)
}

func (s *session) buildMessage() ([]byte, string) {
	from, _ := mail.ParseAddress(s.req.From)
	if s.req.FromName != "" {
		from.Name = s.req.FromName
	}
	_, domain, _ := strings.Cut(from.Address, "@")
	var rnd [12]byte
	randRead(rnd[:])
	msgID := fmt.Sprintf("<%s.%s@%s>", time.Now().UTC().Format("20060102150405"), hex.EncodeToString(rnd[:]), domain)

	subject := s.req.Subject
	if strings.TrimSpace(subject) == "" {
		subject = "SMTP test from Email Test Tools"
	}
	body := s.req.Body
	if strings.TrimSpace(body) == "" {
		body = fmt.Sprintf("Hello!\n\nThis is a test message sent by Email Test Tools.\n\nIf you're reading this, the SMTP settings below work:\n\n  Server:   %s\n  Security: %s\n  Login:    %s\n  Sent at:  %s\n\nNo action is needed.\n",
			s.res.Server, s.req.Security, orDash(s.req.Username), time.Now().Format(time.RFC1123Z))
	}

	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", from.String())
	h("To", strings.Join(s.res.Accepted, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", msgID)
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("X-Mailer", "Email Test Tools")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	io.WriteString(qp, strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	qp.Close()
	return b.Bytes(), msgID
}

// ---------------------------------------------------------------- summary

func (s *session) headline() {
	r := s.rep
	var failed *report.Step
	for _, st := range r.Steps {
		if st.Status == report.Fail {
			failed = st
			break
		}
	}
	switch {
	case failed != nil:
		r.Headline = "Problem at step: " + failed.Title
		r.Advice = failed.Summary
		if failed.Hint != "" {
			r.Advice += " " + failed.Hint
		}
	case s.res.Sent:
		r.Headline = "Your SMTP settings work. The test email was accepted."
		r.Advice = "The server took the message. Check the recipients' inbox and spam folder."
	case s.req.Mode == ModeVerify:
		r.Headline = "Your SMTP settings work. Nothing was sent (check-only mode)."
	default:
		r.Headline = "Test finished."
	}
	if failed == nil && r.Status == report.Warn {
		r.Advice = strings.TrimSpace(r.Advice + " Some steps have warnings worth reading.")
	}
}

// ---------------------------------------------------------------- helpers

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func plural(n int, suffix string) string {
	if n == 1 {
		return ""
	}
	return suffix
}

func orDash(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func isSMTPError(err error) bool {
	var se *smtpError
	return errors.As(err, &se)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
