package netcheck

import (
	"strings"
	"testing"
)

func TestSPFSyntax(t *testing.T) {
	cases := []struct {
		rec      string
		problem  string // substring expected in problems ("" = none)
		warnings int
	}{
		{"v=spf1 include:_spf.google.com ~all", "", 0},
		{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/24 -all", "", 0},
		{"v=spf1 redirect=_spf.example.com", "", 0},
		{"v=spf1 a/24//64 -all", "", 0},
		{"v=spf1include:mxroute.com-all", "no space after v=spf1", 0}, // split TXT pieces
		{"v=spf1 include -all", "needs a domain", 0},
		{"v=spf1 ip4:300.1.1.1 -all", "not a valid IP", 0},
		{"v=spf1 ip4:2001:db8::1 -all", "ip4 needs an IPv4", 0},
		{"v=spf1 ip4:192.0.2.1/33 -all", "prefix length", 0},
		{"v=spf1 inclde:x.com -all", "Unknown term", 0},
		{"v=spf1 -all ~all", "more than once", 1},
		{"v=spf1 ptr -all", "", 1},
		{"v=spf1 -all include:x.com", "", 1},
		{"spf1 -all", "must start", 0},
	}
	for _, c := range cases {
		probs, warns := spfSyntax(c.rec)
		got := strings.Join(probs, " | ")
		if c.problem == "" && len(probs) > 0 {
			t.Errorf("%q: unexpected problems: %s", c.rec, got)
		}
		if c.problem != "" && !strings.Contains(got, c.problem) {
			t.Errorf("%q: want problem containing %q, got %q", c.rec, c.problem, got)
		}
		if len(warns) != c.warnings {
			t.Errorf("%q: want %d warnings, got %v", c.rec, c.warnings, warns)
		}
	}
}

func TestDMARCSyntax(t *testing.T) {
	ok := []string{
		"v=DMARC1; p=none; rua=mailto:d@example.com",
		"v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=r; fo=1; rua=mailto:a@x.com,mailto:b@y.com!10m",
	}
	for _, r := range ok {
		if bad := dmarcSyntax(r); len(bad) > 0 {
			t.Errorf("%q: unexpected %v", r, bad)
		}
	}
	bad := map[string]string{
		"v=DMARC1; p=block":                   "must be none",
		"v=DMARC1; p=none; pct=150":           "0 to 100",
		"v=DMARC1; p=none; rua=d@example.com": "mailto:",
		"v=DMARC1; p=none; adkim=x":           "relaxed",
		"v=DMARC1; p=none; p=reject":          "twice",
		"v=DMARC1; p=none; polcy=reject":      "Unknown tag",
		"v=DMARC1 p=none":                     "start exactly",
	}
	for r, want := range bad {
		got := strings.Join(dmarcSyntax(r), " | ")
		if !strings.Contains(got, want) {
			t.Errorf("%q: want %q in %q", r, want, got)
		}
	}
}

func TestReverseIPv4(t *testing.T) {
	if got := reverseIPv4("45.43.208.37"); got != "37.208.43.45" {
		t.Fatal(got)
	}
}
