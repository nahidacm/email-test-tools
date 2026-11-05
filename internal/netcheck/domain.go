package netcheck

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
)

type DomainRequest struct {
	Domain    string   `json:"domain"`
	Selectors []string `json:"selectors"` // DKIM selectors to try (optional)
	Server    string   `json:"server"`
	// Areas to check: auth, mail, dns, blacklist, web. Empty means all.
	Checks []string `json:"checks"`
}

// Report categories, in display order.
const (
	CatAuth      = "auth"
	CatMail      = "mail"
	CatDNS       = "dns"
	CatBlacklist = "blacklist"
	CatWeb       = "web"
)

var catOrder = map[string]int{CatAuth: 0, CatMail: 1, CatDNS: 2, CatBlacklist: 3, CatWeb: 4}

// mxHost is one mail server with its addresses.
type mxHost struct {
	Pref int
	Host string
	IPs  []string
}

type DomainResult struct {
	MX      []string          `json:"mx"`
	SPF     string            `json:"spf,omitempty"`
	DMARC   string            `json:"dmarc,omitempty"`
	DKIM    map[string]string `json:"dkim"`
	MTASTS  string            `json:"mtaSts,omitempty"`
	TLSRPT  string            `json:"tlsRpt,omitempty"`
	Lookups int               `json:"spfLookups"`
}

// Selectors used by common providers; checked when the user gives none.
var commonSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
	"dkim", "mail", "smtp", "mx", "email", "key1", "key2", "mandrill", "mxvault",
	"zoho", "zmail", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
	"everlytickey1", "cm", "sig1", "amazonses", "pm", "mailjet", "sendgrid", "smtpapi",
}

func CheckDomain(ctx context.Context, req DomainRequest) *report.Report {
	rep := report.New("domain")
	domain := cleanHost(req.Domain)
	res := &DomainResult{DKIM: map[string]string{}, MX: []string{}}
	rep.Data = res
	if domain == "" || !strings.Contains(domain, ".") {
		rep.Add(&report.Step{ID: "input", Title: "Check your settings", Status: report.Fail, Summary: "Enter a domain like example.com (the part after @ in an email address)."})
		rep.Headline = "Nothing to check yet."
		return rep.Finish()
	}
	r := resolver(req.Server)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	want := func(c string) bool {
		if len(req.Checks) == 0 {
			return true
		}
		for _, x := range req.Checks {
			if x == c {
				return true
			}
		}
		return false
	}
	rep.Infof("Checking %s", domain)

	// MX first: the mail-server and blacklist checks need the addresses.
	mxs := checkMX(ctx, rep, r, domain, res)

	var wg sync.WaitGroup
	run := func(c string, fn func()) {
		if want(c) {
			wg.Add(1)
			go func() { defer wg.Done(); fn() }()
		}
	}
	run(CatAuth, func() {
		checkSPF(ctx, rep, r, domain, res)
		policy := checkDMARC(ctx, rep, r, domain, res)
		checkBIMI(ctx, rep, r, domain, policy)
		checkDKIM(ctx, rep, r, domain, req.Selectors, res)
		checkExtras(ctx, rep, r, domain, res)
	})
	run(CatMail, func() { checkMailServers(ctx, rep, r, mxs) })
	run(CatDNS, func() { checkDNSHealth(ctx, rep, r, domain) })
	run(CatBlacklist, func() { checkBlacklists(ctx, rep, r, domain, mxs) })
	run(CatWeb, func() { checkWeb(ctx, rep, r, domain) })
	wg.Wait()

	// Order by area; inside an area, group steps by host (domain-level first).
	// Stable, so each host's steps keep the order they were run in.
	sort.SliceStable(rep.Steps, func(i, j int) bool {
		a, b := rep.Steps[i], rep.Steps[j]
		if ca, cb := catOrder[a.Category], catOrder[b.Category]; ca != cb {
			return ca < cb
		}
		ta, tb := a.Target, b.Target
		if a.Category == CatAuth || a.Category == CatDNS {
			return false // keep run order
		}
		if ta == domain {
			ta = ""
		}
		if tb == domain {
			tb = ""
		}
		return ta < tb
	})

	rep.Finish()
	fails, warns := 0, 0
	for _, s := range rep.Steps {
		switch s.Status {
		case report.Fail:
			fails++
		case report.Warn:
			warns++
		}
	}
	switch {
	case fails > 0:
		rep.Headline = fmt.Sprintf("%s has %d problem(s) and %d warning(s).", domain, fails, warns)
		rep.Advice = "Fix the red items first. Changes are made at your DNS provider (where you bought or host the domain) and can take up to a few hours to apply."
	case warns > 0:
		rep.Headline = fmt.Sprintf("%s is mostly set up, with %d thing(s) to improve.", domain, warns)
		rep.Advice = "Yellow items won't break email, but fixing them helps your messages avoid the spam folder."
	default:
		rep.Headline = fmt.Sprintf("%s looks well set up for email.", domain)
	}
	return rep
}

func txt(ctx context.Context, rep *report.Report, r *net.Resolver, name string) ([]string, error) {
	rep.Sent("TXT %s", name)
	v, err := r.LookupTXT(ctx, name)
	if err != nil && !isNotFound(err) {
		rep.Errf("TXT %s: %v", name, err)
		return nil, err
	}
	for _, x := range v {
		rep.Recv("%s TXT %q", name, x)
	}
	return v, nil
}

// DocsURL is where each check's "More info" link points.
const DocsURL = "https://github.com/nahidacm/email-test-tools/blob/main/docs/checks.md#"

func checkMX(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, res *DomainResult) (hosts []mxHost) {
	st := rep.BeginIn(CatMail, domain, "mx", "Can this domain receive email? (MX)").Info(DocsURL + "mx")
	rep.Sent("MX %s", domain)
	mx, err := r.LookupMX(ctx, domain)
	if err != nil && !isNotFound(err) {
		st.Detail("%v", err)
		st.Set(report.Fail, "We couldn't look up mail servers: "+friendlyDNSErr(err), "")
		return nil
	}
	if len(mx) == 1 && (mx[0].Host == "." || mx[0].Host == "") {
		st.Set(report.Info, "This domain says it never accepts email (null MX).", "That's intentional for domains that only send, or don't use email at all.")
		return nil
	}
	if len(mx) == 0 {
		st.Set(report.Fail, "No mail servers are listed, so nobody can send email to this domain.",
			"Add MX records at your DNS provider. Your email host (Google Workspace, Microsoft 365, your web host…) tells you which values to use.")
		return nil
	}
	bad := 0
	for _, m := range mx {
		rep.Recv("MX %d %s", m.Pref, m.Host)
		res.MX = append(res.MX, fmt.Sprintf("%d %s", m.Pref, m.Host))
		ips, err := r.LookupHost(ctx, m.Host)
		if err != nil || len(ips) == 0 {
			bad++
			st.Detail("%d %s → does not resolve (%v)", m.Pref, m.Host, err)
			continue
		}
		st.Detail("%d %s → %s", m.Pref, m.Host, strings.Join(ips, ", "))
		hosts = append(hosts, mxHost{Pref: int(m.Pref), Host: strings.TrimSuffix(m.Host, "."), IPs: ips})
	}
	switch {
	case bad == len(mx):
		st.Set(report.Fail, "Mail servers are listed, but none of them exist.", "The MX records point to names that don't resolve. Check them for typos.")
	case bad > 0:
		st.Set(report.Warn, fmt.Sprintf("%d of %d mail servers can't be found.", bad, len(mx)), "Remove or fix the MX records that don't resolve.")
	default:
		st.Set(report.OK, fmt.Sprintf("Yes: %d mail server(s) are set up.", len(mx)), "")
	}
	return hosts
}

func checkSPF(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, res *DomainResult) {
	st := rep.BeginIn(CatAuth, domain, "spf", "Who may send as this domain? (SPF)").Info(DocsURL + "spf")
	recs, err := txt(ctx, rep, r, domain)
	if err != nil {
		st.Set(report.Fail, "Lookup failed: "+friendlyDNSErr(err), "")
		return
	}
	var spf []string
	for _, t := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = append(spf, t)
		}
	}
	switch len(spf) {
	case 0:
		st.Set(report.Fail, "No SPF record. Receiving servers can't tell which servers are allowed to send your email, so it's more likely to land in spam.",
			"Add a TXT record on your domain starting with v=spf1. Your email provider gives you the exact value, e.g. “v=spf1 include:_spf.google.com ~all”.")
		return
	case 1:
	default:
		for _, s := range spf {
			st.Detail("%s", s)
		}
		st.Set(report.Fail, fmt.Sprintf("There are %d SPF records, but only one is allowed. Receivers treat this as broken.", len(spf)),
			"Merge them into a single v=spf1 record (combine the include: parts, keep one “all” at the end).")
		return
	}
	rec := spf[0]
	res.SPF = rec
	st.Detail("Record: %s", rec)

	problems, warnings := spfSyntax(rec)
	if len(problems) > 0 {
		st.Details = append(st.Details, problems...)
		st.MoreInfo = DocsURL + "spf-syntax"
		st.Set(report.Fail, "The SPF record has invalid syntax, so receivers ignore it (as if there were no SPF at all).", strings.Join(problems, " "))
		return
	}

	lookups, notes := spfLookups(ctx, rep, r, domain, rec, 0, map[string]bool{})
	res.Lookups = lookups
	st.Detail("DNS lookups needed: %d of 10 allowed", lookups)
	st.Details = append(st.Details, notes...)

	fields := strings.Fields(strings.ToLower(rec))
	all := ""
	for _, f := range fields {
		if strings.HasSuffix(f, "all") && len(f) <= 4 {
			all = f
		}
	}
	issues := warnings
	status := report.OK
	if len(warnings) > 0 {
		status = report.Warn
	}
	summary := "SPF is set up."
	switch all {
	case "-all":
		summary = "SPF is set up and strict: mail from unlisted servers should be rejected."
	case "~all":
		summary = "SPF is set up. Mail from unlisted servers is marked suspicious (~all)."
	case "?all":
		status = report.Warn
		issues = append(issues, "The record ends in “?all”, which means “no opinion” and gives little protection. Use ~all or -all.")
	case "+all", "all":
		status = report.Fail
		issues = append(issues, "The record ends in “+all”, which allows ANY server in the world to send as your domain. Change it to ~all or -all.")
	default:
		if !strings.Contains(rec, "redirect=") {
			status = report.Warn
			issues = append(issues, "The record has no “all” rule at the end. Add ~all or -all.")
		}
	}
	if lookups > 10 {
		status = report.Fail
		issues = append(issues, fmt.Sprintf("SPF needs %d DNS lookups, but the limit is 10. Receivers will treat it as broken. Remove unused include: entries or use a flattening service.", lookups))
	} else if lookups >= 8 && status == report.OK {
		status = report.Warn
		issues = append(issues, fmt.Sprintf("SPF uses %d of 10 allowed DNS lookups. Adding another service may break it.", lookups))
	}
	if status != report.OK {
		summary = "SPF works, but could be improved."
		if status == report.Fail {
			summary = "SPF exists but has problems."
		}
	}
	st.Set(status, summary, strings.Join(issues, " "))
}

// spfLookups counts DNS-querying mechanisms, following include/redirect.
func spfLookups(ctx context.Context, rep *report.Report, r *net.Resolver, domain, rec string, depth int, seen map[string]bool) (int, []string) {
	if depth > 10 {
		return 0, []string{"include chain too deep"}
	}
	n := 0
	var notes []string
	for _, f := range strings.Fields(rec)[1:] {
		f = strings.ToLower(strings.TrimLeft(f, "+-~?"))
		var target string
		switch {
		case strings.HasPrefix(f, "include:"):
			target = strings.TrimPrefix(f, "include:")
		case strings.HasPrefix(f, "redirect="):
			target = strings.TrimPrefix(f, "redirect=")
		case f == "a" || f == "mx" || f == "ptr" || strings.HasPrefix(f, "a:") || strings.HasPrefix(f, "a/") ||
			strings.HasPrefix(f, "mx:") || strings.HasPrefix(f, "mx/") || strings.HasPrefix(f, "ptr:") || strings.HasPrefix(f, "exists:"):
			n++
			continue
		default:
			continue
		}
		n++
		if seen[target] {
			continue
		}
		seen[target] = true
		recs, err := txt(ctx, rep, r, target)
		var sub string
		for _, t := range recs {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				sub = t
			}
		}
		if err != nil || sub == "" {
			notes = append(notes, fmt.Sprintf("⚠ %s has no SPF record (broken include)", target))
			continue
		}
		c, nn := spfLookups(ctx, rep, r, target, sub, depth+1, seen)
		notes = append(notes, fmt.Sprintf("%s%s → %d more lookup(s)", strings.Repeat("  ", depth), target, c))
		notes = append(notes, nn...)
		n += c
	}
	return n, notes
}

func tag(rec, key string) string {
	for _, p := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// checkDMARC returns the effective policy (none/quarantine/reject) and pct.
func checkDMARC(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, res *DomainResult) (policy string) {
	st := rep.BeginIn(CatAuth, "_dmarc."+domain, "dmarc", "What happens to fake email? (DMARC)").Info(DocsURL + "dmarc")
	find := func(d string) string {
		recs, _ := txt(ctx, rep, r, "_dmarc."+d)
		for _, t := range recs {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t)), "V=DMARC1") {
				return t
			}
		}
		return ""
	}
	rec := find(domain)
	inherited := ""
	if rec == "" {
		// Fall back to the parent domain (simple organisational-domain guess).
		if parts := strings.Split(domain, "."); len(parts) > 2 {
			parent := strings.Join(parts[len(parts)-2:], ".")
			if rec = find(parent); rec != "" {
				inherited = parent
			}
		}
	}
	if rec == "" {
		st.Set(report.Fail, "No DMARC policy. Anyone can send email pretending to be this domain, and Gmail/Yahoo/Outlook now expect DMARC from senders.",
			fmt.Sprintf("Add a TXT record named _dmarc.%s with a value like “v=DMARC1; p=none; rua=mailto:dmarc@%s”. Start with p=none to monitor, then move to quarantine or reject.", domain, domain))
		return ""
	}
	res.DMARC = rec
	st.Detail("Record: %s", rec)
	if inherited != "" {
		st.Detail("Inherited from parent domain %s", inherited)
	}
	p := strings.ToLower(tag(rec, "p"))
	sp := strings.ToLower(tag(rec, "sp"))
	if inherited != "" && sp != "" {
		p = sp
	}
	rua := tag(rec, "rua")
	pct := tag(rec, "pct")
	if rua != "" {
		st.Detail("Reports go to: %s", rua)
	}
	var hint []string
	if bad := dmarcSyntax(rec); len(bad) > 0 {
		st.Details = append(st.Details, bad...)
		st.Set(report.Fail, "The DMARC record has errors.", strings.Join(bad, " "))
		return ""
	}
	policy = p
	if pct != "" && pct != "100" {
		policy += "/" + pct
	}
	if rua == "" {
		hint = append(hint, "Add rua=mailto:you@yourdomain to receive reports about who sends email as your domain.")
	}
	if pct != "" && pct != "100" {
		hint = append(hint, fmt.Sprintf("The policy only applies to %s%% of messages (pct=%s).", pct, pct))
	}
	switch p {
	case "reject":
		st.Set(report.OK, "DMARC is strict: fake email claiming to be from this domain is rejected.", strings.Join(hint, " "))
	case "quarantine":
		st.Set(report.OK, "DMARC is active: fake email claiming to be from this domain goes to spam.", strings.Join(hint, " "))
	case "none":
		hint = append([]string{"Once reports show all your real email passes, change p=none to p=quarantine, then p=reject."}, hint...)
		st.Set(report.Warn, "DMARC is in monitor-only mode (p=none): fake email isn't blocked yet.", strings.Join(hint, " "))
	default:
		st.Set(report.Fail, "The DMARC record is invalid: the p= policy is missing or unknown.", "The record must include p=none, p=quarantine or p=reject.")
	}
	return policy
}

// dmarcSyntax checks tag values (RFC 7489 §6.3).
func dmarcSyntax(rec string) []string {
	var bad []string
	parts := strings.Split(rec, ";")
	if strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", "") != "v=DMARC1" {
		bad = append(bad, "The record must start exactly with “v=DMARC1;”.")
	}
	seen := map[string]bool{}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok {
			bad = append(bad, fmt.Sprintf("“%s” is not a tag=value pair.", p))
			continue
		}
		if seen[k] {
			bad = append(bad, fmt.Sprintf("Tag “%s” appears twice.", k))
		}
		seen[k] = true
		lv := strings.ToLower(v)
		switch k {
		case "p", "sp":
			if lv != "none" && lv != "quarantine" && lv != "reject" {
				bad = append(bad, fmt.Sprintf("%s=%s: must be none, quarantine or reject.", k, v))
			}
		case "pct":
			if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 100 {
				bad = append(bad, fmt.Sprintf("pct=%s: must be a number from 0 to 100.", v))
			}
		case "adkim", "aspf":
			if lv != "r" && lv != "s" {
				bad = append(bad, fmt.Sprintf("%s=%s: must be r (relaxed) or s (strict).", k, v))
			}
		case "rua", "ruf":
			for _, u := range strings.Split(v, ",") {
				if u = strings.TrimSpace(u); !strings.HasPrefix(strings.ToLower(u), "mailto:") || !strings.Contains(u, "@") {
					bad = append(bad, fmt.Sprintf("%s: “%s” must look like mailto:reports@example.com.", k, u))
				}
			}
		case "fo", "rf", "ri", "np", "t", "psd":
		default:
			bad = append(bad, fmt.Sprintf("Unknown tag “%s”.", k))
		}
	}
	return bad
}

func checkBIMI(ctx context.Context, rep *report.Report, r *net.Resolver, domain, policy string) {
	st := rep.BeginIn(CatAuth, "default._bimi."+domain, "bimi", "Brand logo in inboxes (BIMI)").Info(DocsURL + "bimi")
	var rec string
	for _, t := range mustTXT(ctx, rep, r, "default._bimi."+domain) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=bimi1") {
			rec = t
		}
	}
	enforced := policy == "quarantine" || policy == "reject"
	if rec == "" {
		hint := "Optional. BIMI shows your logo next to your emails in Gmail, Yahoo and Apple Mail."
		if !enforced {
			hint += " It requires DMARC with p=quarantine or p=reject at 100%, which this domain doesn't have yet."
		}
		st.Set(report.Info, "Not set up: your logo won't appear in recipients' inboxes.", hint)
		return
	}
	st.Detail("Record: %s", rec)
	logo := tag(rec, "l")
	if logo != "" {
		st.Detail("Logo: %s", logo)
	}
	if a := tag(rec, "a"); a != "" {
		st.Detail("Certificate (VMC/CMC): %s", a)
	}
	switch {
	case !enforced:
		st.Set(report.Warn, "BIMI is published but won't work yet.", "BIMI requires DMARC with p=quarantine or p=reject at 100%.")
	case !strings.HasPrefix(strings.ToLower(logo), "https://"):
		st.Set(report.Warn, "BIMI is published, but the logo address (l=) is missing or not https.", "Point l= to an https:// URL of an SVG Tiny PS logo.")
	case tag(rec, "a") == "":
		st.Set(report.OK, "BIMI is set up. Gmail and Apple Mail also need a mark certificate (a=) to show the logo.", "")
	default:
		st.Set(report.OK, "BIMI is set up with a logo and certificate.", "")
	}
}

func checkDKIM(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, selectors []string, res *DomainResult) {
	st := rep.BeginIn(CatAuth, domain, "dkim", "Are messages signed? (DKIM)").Info(DocsURL + "dkim")
	userGiven := false
	var sels []string
	for _, s := range selectors {
		if s = strings.TrimSpace(s); s != "" {
			sels = append(sels, s)
			userGiven = true
		}
	}
	if !userGiven {
		sels = commonSelectors
	}
	type hit struct{ sel, rec string }
	var mu sync.Mutex
	var hits []hit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, sel := range sels {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := sel + "._domainkey." + domain
			recs, _ := txt(ctx, rep, r, name)
			rec := strings.Join(recs, "")
			if rec == "" {
				// Some providers publish a CNAME to their own key; LookupTXT follows it.
				return
			}
			if strings.Contains(rec, "p=") || strings.Contains(strings.ToLower(rec), "v=dkim1") {
				mu.Lock()
				hits = append(hits, hit{sel, rec})
				mu.Unlock()
			}
		}(sel)
	}
	wg.Wait()

	if len(hits) == 0 {
		if userGiven {
			st.Set(report.Fail, fmt.Sprintf("No DKIM key found for selector(s): %s.", strings.Join(sels, ", ")),
				"Check the selector name. Open an email sent from this domain, view the original/headers, and look for “DKIM-Signature: … s=SELECTOR”.")
		} else {
			st.Set(report.Warn, fmt.Sprintf("No DKIM key found under %d common names.", len(sels)),
				"DKIM may still be set up under a custom name (a “selector”). Find it in a sent email's headers (DKIM-Signature … s=SELECTOR) and enter it in the DKIM selector box. If DKIM isn't set up, turn it on in your email provider's admin panel.")
		}
		return
	}
	var weak []string
	for _, h := range hits {
		res.DKIM[h.sel] = h.rec
		desc := describeDKIM(h.rec)
		st.Detail("%s._domainkey: %s", h.sel, desc)
		if strings.Contains(desc, "revoked") || strings.Contains(desc, "1024") || strings.Contains(desc, "512") {
			weak = append(weak, h.sel)
		}
	}
	names := make([]string, 0, len(hits))
	for _, h := range hits {
		names = append(names, h.sel)
	}
	if len(weak) > 0 {
		st.Set(report.Warn, fmt.Sprintf("DKIM keys found (%s), but some are weak or revoked (%s).", strings.Join(names, ", "), strings.Join(weak, ", ")),
			"Use 2048-bit keys. Most providers let you rotate to a new key in their admin panel.")
		return
	}
	st.Set(report.OK, fmt.Sprintf("Yes: DKIM signing keys found (%s).", strings.Join(names, ", ")), "")
}

func describeDKIM(rec string) string {
	p := tag(rec, "p")
	k := strings.ToLower(tag(rec, "k"))
	if k == "" {
		k = "rsa"
	}
	if p == "" {
		return "key revoked (empty p=)"
	}
	if k == "rsa" {
		der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(p, " ", ""))
		if err == nil {
			if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
				if rk, ok := pub.(*rsa.PublicKey); ok {
					return fmt.Sprintf("RSA %d-bit key", rk.N.BitLen())
				}
			} else if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
				return fmt.Sprintf("RSA %d-bit key", pub.N.BitLen())
			}
		}
		return "RSA key"
	}
	return strings.ToUpper(k) + " key"
}

func checkExtras(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, res *DomainResult) {
	st := rep.BeginIn(CatAuth, domain, "extras", "Extra protection (MTA-STS, TLS reporting)").Info(DocsURL + "mta-sts")
	for _, t := range mustTXT(ctx, rep, r, "_mta-sts."+domain) {
		if strings.HasPrefix(strings.ToLower(t), "v=stsv1") {
			res.MTASTS = t
		}
	}
	for _, t := range mustTXT(ctx, rep, r, "_smtp._tls."+domain) {
		if strings.HasPrefix(strings.ToLower(t), "v=tlsrptv1") {
			res.TLSRPT = t
		}
	}
	var have []string
	if res.MTASTS != "" {
		have = append(have, "MTA-STS")
		st.Detail("MTA-STS: %s", res.MTASTS)
	}
	if res.TLSRPT != "" {
		have = append(have, "TLS-RPT")
		st.Detail("TLS-RPT: %s", res.TLSRPT)
	}
	if len(have) == 0 {
		st.Set(report.Info, "Not set up. These optional settings force other servers to use encryption when delivering to you.", "")
		return
	}
	st.Set(report.OK, "Enabled: "+strings.Join(have, ", ")+".", "")
}

func mustTXT(ctx context.Context, rep *report.Report, r *net.Resolver, name string) []string {
	v, _ := txt(ctx, rep, r, name)
	return v
}
