package smtpcheck

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/nahidacm/email-test-tools/internal/report"
)

// fakeSMTP is a tiny scripted SMTP server for tests (no TLS).
type fakeSMTP struct {
	user, pass string
	rejectRcpt string
	gotData    string
}

func (f *fakeSMTP) serve(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { c.Write([]byte(s + "\r\n")) }
	w("220 fake.test ESMTP ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-fake.test hello")
			w("250-SIZE 1000000")
			w("250 AUTH PLAIN LOGIN")
		case strings.HasPrefix(up, "AUTH PLAIN "):
			want := base64.StdEncoding.EncodeToString([]byte("\x00" + f.user + "\x00" + f.pass))
			if line[len("AUTH PLAIN "):] == want {
				w("235 2.7.0 Authentication successful")
			} else {
				w("535 5.7.8 Authentication credentials invalid")
			}
		case strings.HasPrefix(up, "MAIL FROM:"):
			w("250 2.1.0 OK")
		case strings.HasPrefix(up, "RCPT TO:"):
			if f.rejectRcpt != "" && strings.Contains(line, f.rejectRcpt) {
				w("550 5.1.1 User unknown")
			} else {
				w("250 2.1.5 OK")
			}
		case up == "DATA":
			w("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.gotData = b.String()
			w("250 2.0.0 queued as ABC123")
		case up == "RSET":
			w("250 OK")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("502 command not implemented")
		}
	}
}

func stepStatus(rep *report.Report, id string) report.Status {
	for _, s := range rep.Steps {
		if s.ID == id {
			return s.Status
		}
	}
	return ""
}

func TestSendSuccess(t *testing.T) {
	f := &fakeSMTP{user: "u@test", pass: "secret"}
	host, port := f.serve(t)
	rep := Run(context.Background(), Request{
		Host: host, Port: port, Security: SecNone, Username: "u@test", Password: "secret",
		From: "u@test", To: []string{"a@test, b@test"}, Mode: ModeSend,
	})
	res := rep.Data.(*Result)
	if !res.Sent || len(res.Accepted) != 2 {
		t.Fatalf("expected sent to 2, got sent=%v accepted=%v; headline=%q", res.Sent, res.Accepted, rep.Headline)
	}
	if !strings.Contains(f.gotData, "Subject: SMTP test from Email Test Tools") {
		t.Errorf("message missing default subject:\n%s", f.gotData)
	}
	for _, l := range rep.Log {
		if strings.Contains(l.Text, base64.StdEncoding.EncodeToString([]byte("\x00u@test\x00secret"))) {
			t.Fatal("password leaked into log")
		}
	}
	if stepStatus(rep, "auth") != report.OK || stepStatus(rep, "data") != report.OK {
		t.Errorf("unexpected step statuses: %+v", rep.Steps)
	}
}

func TestWrongPassword(t *testing.T) {
	f := &fakeSMTP{user: "u@test", pass: "secret"}
	host, port := f.serve(t)
	rep := Run(context.Background(), Request{
		Host: host, Port: port, Security: SecNone, Username: "u@test", Password: "nope",
		From: "u@test", To: []string{"a@test"},
	})
	if rep.Status != report.Fail || stepStatus(rep, "auth") != report.Fail {
		t.Fatalf("expected auth failure, got %s", rep.Status)
	}
	if !strings.Contains(rep.Advice, "username or password was rejected") {
		t.Errorf("advice not friendly: %q", rep.Advice)
	}
}

func TestVerifyModeAndPartialReject(t *testing.T) {
	f := &fakeSMTP{rejectRcpt: "bad@test"}
	host, port := f.serve(t)
	rep := Run(context.Background(), Request{
		Host: host, Port: port, Security: SecAuto, From: "u@test",
		To: []string{"good@test", "bad@test"}, Mode: ModeVerify,
	})
	if s := stepStatus(rep, "rcpt"); s != report.Warn {
		t.Errorf("rcpt: want warn, got %s", s)
	}
	if s := stepStatus(rep, "data"); s != report.Skip {
		t.Errorf("data: want skip, got %s", s)
	}
	if f.gotData != "" {
		t.Error("verify mode must not send DATA")
	}
}

func TestRefusesPasswordWithoutTLS(t *testing.T) {
	f := &fakeSMTP{user: "u", pass: "p"}
	host, port := f.serve(t)
	rep := Run(context.Background(), Request{
		Host: host, Port: port, Security: SecAuto, Username: "u", Password: "p",
		From: "u@test", To: []string{"a@test"},
	})
	if stepStatus(rep, "auth") != report.Fail {
		t.Fatal("expected auth to be refused over plaintext in auto mode")
	}
}

func TestConnectionRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	rep := Run(context.Background(), Request{Host: "127.0.0.1", Port: port, From: "a@test", To: []string{"b@test"}})
	if stepStatus(rep, "connect") != report.Fail || !strings.Contains(rep.Advice, "nothing is accepting connections on port "+strconv.Itoa(port)) {
		t.Fatalf("unexpected: %q", rep.Advice)
	}
}

func TestValidation(t *testing.T) {
	rep := Run(context.Background(), Request{Host: "https://smtp.x.com", Port: 0, From: "nope", To: []string{"x"}})
	if stepStatus(rep, "input") != report.Fail || len(rep.Steps) != 1 {
		t.Fatalf("expected only a failed input step, got %+v", rep.Steps)
	}
}
