package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
)

type DNSRequest struct {
	Name   string   `json:"name"`
	Types  []string `json:"types"`
	Server string   `json:"server"` // optional, e.g. 1.1.1.1
}

// resolver returns the system resolver, or one that talks to a specific DNS server.
func resolver(server string) *net.Resolver {
	server = strings.TrimSpace(server)
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
}

var typeExplain = map[string]string{
	"A":     "IPv4 addresses: where the name points",
	"AAAA":  "IPv6 addresses",
	"MX":    "Mail servers that receive email for this domain",
	"TXT":   "Text records: SPF, verification codes and other settings",
	"NS":    "Name servers that are in charge of this domain",
	"CNAME": "Alias: this name is another name in disguise",
	"PTR":   "Reverse lookup: the name behind an IP address",
}

func LookupDNS(ctx context.Context, req DNSRequest) *report.Report {
	rep := report.New("dns")
	name := cleanHost(req.Name)
	r := resolver(req.Server)
	data := map[string][]string{}
	rep.Data = data

	if name == "" {
		rep.Add(&report.Step{ID: "input", Title: "Check your settings", Status: report.Fail, Summary: "Enter a domain name or IP address."})
		rep.Headline = "Nothing to look up yet."
		return rep.Finish()
	}
	types := req.Types
	isIP := net.ParseIP(name) != nil
	if isIP {
		types = []string{"PTR"}
	} else if len(types) == 0 {
		types = []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME"}
	}
	srv := "your system's DNS"
	if req.Server != "" {
		srv = req.Server
	}
	rep.Infof("Resolving %s via %s", name, srv)

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	found := 0
	for _, t := range types {
		t = strings.ToUpper(t)
		st := rep.Begin(strings.ToLower(t), t+" records")
		vals, err := lookup(cctx, r, t, name)
		for _, v := range vals {
			st.Detail("%s", v)
			rep.Recv("%s %s %s", name, t, v)
		}
		data[t] = vals
		switch {
		case err != nil && !isNotFound(err):
			rep.Errf("%s %s: %v", name, t, err)
			st.Detail("Error: %v", err)
			st.Set(report.Fail, "The lookup failed: "+friendlyDNSErr(err), "")
		case len(vals) == 0:
			st.Set(report.Info, "None found. "+typeExplain[t]+".", "")
		default:
			found++
			st.Set(report.OK, fmt.Sprintf("%d found. %s.", len(vals), typeExplain[t]), "")
		}
	}
	rep.Finish()
	if found == 0 {
		rep.Status = report.Warn
		rep.Headline = fmt.Sprintf("No DNS records found for %s.", name)
		rep.Advice = "Check the spelling. A brand-new domain or recent change can take a while (up to 48 hours) to show up everywhere."
	} else {
		rep.Headline = fmt.Sprintf("DNS records for %s via %s.", name, srv)
		rep.Status = report.OK
	}
	return rep
}

func lookup(ctx context.Context, r *net.Resolver, t, name string) ([]string, error) {
	var out []string
	switch t {
	case "A", "AAAA":
		ips, err := r.LookupIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[t], name)
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out, err
	case "MX":
		mx, err := r.LookupMX(ctx, name)
		for _, m := range mx {
			out = append(out, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
		return out, err
	case "TXT":
		return r.LookupTXT(ctx, name)
	case "NS":
		ns, err := r.LookupNS(ctx, name)
		for _, n := range ns {
			out = append(out, n.Host)
		}
		return out, err
	case "CNAME":
		c, err := r.LookupCNAME(ctx, name)
		if err == nil && strings.TrimSuffix(c, ".") != strings.TrimSuffix(name, ".") {
			out = append(out, c)
		}
		return out, err
	case "PTR":
		return r.LookupAddr(ctx, name)
	}
	return nil, fmt.Errorf("unsupported record type %s", t)
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func friendlyDNSErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsTimeout:
			return "the DNS server didn't answer in time."
		case de.IsTemporary:
			return "the DNS server had a temporary problem."
		}
	}
	return err.Error()
}
