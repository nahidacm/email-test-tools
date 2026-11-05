// Package netcheck contains network diagnostics: port reachability,
// DNS lookups, email domain health and TLS certificate checks.
package netcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"email-test-tools/internal/report"
)

// PortInfo describes well-known ports in plain words.
var PortInfo = map[int]string{
	21: "FTP", 22: "SSH", 25: "SMTP (server-to-server mail)", 53: "DNS",
	80: "Web (HTTP)", 110: "POP3 (download mail)", 143: "IMAP (read mail)",
	443: "Web (HTTPS)", 465: "SMTP with SSL/TLS (sending mail)",
	587: "SMTP submission with STARTTLS (sending mail)", 993: "IMAP with SSL/TLS (read mail)",
	995: "POP3 with SSL/TLS (download mail)", 2525: "Alternative SMTP (sending mail)",
	4190: "ManageSieve (mail filters)",
}

// Ports where the server speaks first, so we can read a banner.
var bannerPorts = map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true, 587: true, 2525: true}

// Ports that are TLS from the first byte.
var implicitTLSPorts = map[int]bool{443: true, 465: true, 993: true, 995: true}

type PortRequest struct {
	Host       string `json:"host"`
	Ports      []int  `json:"ports"`
	TimeoutSec int    `json:"timeoutSec"`
}

type PortResult struct {
	Port      int    `json:"port"`
	Service   string `json:"service"`
	State     string `json:"state"` // open | closed | filtered | error
	LatencyMs int64  `json:"latencyMs"`
	Banner    string `json:"banner,omitempty"`
	TLS       string `json:"tls,omitempty"`
	Error     string `json:"error,omitempty"`
}

func CheckPorts(ctx context.Context, req PortRequest) *report.Report {
	rep := report.New("ports")
	host := cleanHost(req.Host)
	timeout := secs(req.TimeoutSec, 5, 30)
	results := []*PortResult{}
	rep.Data = &results

	if host == "" || len(req.Ports) == 0 {
		rep.Add(&report.Step{ID: "input", Title: "Check your settings", Status: report.Fail, Summary: "Enter a server address and at least one port."})
		rep.Headline = "Nothing to test yet."
		return rep.Finish()
	}
	if len(req.Ports) > 64 {
		req.Ports = req.Ports[:64]
	}
	rep.Infof("Checking %d port(s) on %s with %s timeout", len(req.Ports), host, timeout)

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range req.Ports {
		if p <= 0 || p > 65535 {
			continue
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			r := probePort(ctx, rep, host, port, timeout)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	open := 0
	for _, r := range results {
		st := &report.Step{ID: fmt.Sprintf("port-%d", r.Port), Title: fmt.Sprintf("Port %d · %s", r.Port, r.Service), DurationMs: r.LatencyMs}
		switch r.State {
		case "open":
			open++
			st.Status = report.OK
			st.Summary = "Open: a service is answering."
			if r.TLS != "" {
				st.Summary = "Open, and it speaks secure SSL/TLS."
				st.Detail("TLS: %s", r.TLS)
			}
			if r.Banner != "" {
				st.Detail("Banner: %s", r.Banner)
			}
		case "closed":
			st.Status = report.Fail
			st.Summary = "Closed: the server is reachable, but nothing listens on this port."
			st.Hint = "The service isn't running on this port, or this server doesn't offer it."
		case "filtered":
			st.Status = report.Fail
			st.Summary = "Blocked: no answer at all (timed out)."
			st.Hint = "A firewall is silently dropping the connection, either on your network, your internet provider, or at the server."
			if r.Port == 25 {
				st.Hint += " Outgoing port 25 is blocked by most home ISPs and cloud providers. Use 587 or 465 for sending."
			}
		default:
			st.Status = report.Fail
			st.Summary = "Couldn't test: " + r.Error
		}
		st.Detail("%dms", r.LatencyMs)
		if r.Error != "" {
			st.Detail("Error: %s", r.Error)
		}
		rep.Add(st)
	}
	rep.Finish()
	switch {
	case open == len(results):
		rep.Headline = fmt.Sprintf("All %d port(s) are reachable on %s.", open, host)
	case open == 0:
		rep.Headline = fmt.Sprintf("None of the ports are reachable on %s.", host)
		rep.Advice = "If every port is blocked, check the server name, your internet connection, or try from another network to rule out a local firewall."
	default:
		rep.Headline = fmt.Sprintf("%d of %d port(s) are reachable on %s.", open, len(results), host)
		rep.Status = report.Warn
	}
	return rep
}

func probePort(ctx context.Context, rep *report.Report, host string, port int, timeout time.Duration) *PortResult {
	r := &PortResult{Port: port, Service: PortInfo[port]}
	if r.Service == "" {
		r.Service = "Custom port"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	t := time.Now()
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	r.LatencyMs = time.Since(t).Milliseconds()
	if err != nil {
		r.Error = err.Error()
		var ne net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			r.State = "closed"
		case errors.As(err, &ne) && ne.Timeout():
			r.State = "filtered"
		default:
			r.State = "error"
		}
		rep.Errf("%s → %s (%v)", addr, r.State, err)
		return r
	}
	defer c.Close()
	r.State = "open"
	rep.Infof("%s → open in %dms", addr, r.LatencyMs)

	switch {
	case bannerPorts[port]:
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if line, err := bufio.NewReader(c).ReadString('\n'); err == nil {
			r.Banner = strings.TrimSpace(line)
			rep.Recv("%d: %s", port, r.Banner)
		}
	case implicitTLSPorts[port]:
		tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(timeout))
		if err := tc.Handshake(); err == nil {
			cs := tc.ConnectionState()
			r.TLS = tls.VersionName(cs.Version) + " " + tls.CipherSuiteName(cs.CipherSuite)
			rep.Infof("%d: TLS %s", port, r.TLS)
		} else {
			rep.Errf("%d: TLS handshake failed: %v", port, err)
		}
	}
	return r
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	for _, p := range []string{"http://", "https://", "smtp://", "smtps://"} {
		h = strings.TrimPrefix(h, p)
	}
	h, _, _ = strings.Cut(h, "/")
	if at := strings.LastIndex(h, "@"); at >= 0 { // user typed an email address
		h = h[at+1:]
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func secs(v, def, max int) time.Duration {
	if v <= 0 || v > max {
		v = def
	}
	return time.Duration(v) * time.Second
}
