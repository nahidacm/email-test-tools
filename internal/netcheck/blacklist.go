package netcheck

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
)

// dnsbl is a DNS-based blocklist. Major lists are widely used by receivers;
// a listing on a minor/aggressive list is reported as a warning only.
type dnsbl struct {
	Zone  string
	Name  string
	Major bool
	Site  string // where to look up / request removal
}

var ipBlacklists = []dnsbl{
	{"zen.spamhaus.org", "Spamhaus ZEN", true, "https://check.spamhaus.org/"},
	{"bl.spamcop.net", "SpamCop", true, "https://www.spamcop.net/bl.shtml"},
	{"b.barracudacentral.org", "Barracuda", true, "https://www.barracudacentral.org/lookups"},
	{"psbl.surriel.com", "PSBL", true, "https://psbl.org/"},
	{"bl.mailspike.net", "Mailspike", true, "https://mailspike.io/"},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT Level 1", true, "https://www.uceprotect.net/en/rblcheck.php"},
	{"dnsbl.sorbs.net", "SORBS", false, "http://www.sorbs.net/"},
	{"dnsbl-2.uceprotect.net", "UCEPROTECT Level 2 (network)", false, "https://www.uceprotect.net/en/rblcheck.php"},
	{"dnsbl-3.uceprotect.net", "UCEPROTECT Level 3 (provider)", false, "https://www.uceprotect.net/en/rblcheck.php"},
	{"dnsbl.dronebl.org", "DroneBL", false, "https://dronebl.org/lookup"},
	{"truncate.gbudb.net", "GBUdb Truncate", false, "https://www.gbudb.com/truncate/"},
	{"bl.blocklist.de", "blocklist.de", false, "https://www.blocklist.de/en/search.html"},
	{"dnsbl.spfbl.net", "SPFBL", false, "https://spfbl.net/en/dnsbl/"},
	{"rbl.interserver.net", "InterServer", false, "https://rbl.interserver.net/"},
	{"bl.spameatingmonkey.net", "Spam Eating Monkey", false, "https://spameatingmonkey.com/"},
	{"backscatter.spameatingmonkey.net", "SEM Backscatter", false, "https://spameatingmonkey.com/"},
	{"spam.spamrats.com", "SpamRATS Spam", false, "https://www.spamrats.com/lookup.php"},
	{"dyna.spamrats.com", "SpamRATS Dynamic", false, "https://www.spamrats.com/lookup.php"},
	{"noptr.spamrats.com", "SpamRATS NoPtr", false, "https://www.spamrats.com/lookup.php"},
	{"bl.nordspam.com", "NordSpam", false, "https://www.nordspam.com/"},
	{"ubl.unsubscore.com", "Lashback UBL", false, "https://blacklist.lashback.com/"},
	{"rbl.0spam.org", "0spam", false, "https://0spam.org/"},
	{"all.s5h.net", "s5h.net", false, "https://www.usenix.org.uk/content/rbl.html"},
}

var domainBlacklists = []dnsbl{
	{"dbl.spamhaus.org", "Spamhaus DBL", true, "https://check.spamhaus.org/"},
	{"multi.surbl.org", "SURBL", true, "https://www.surbl.org/surbl-analysis"},
	{"multi.uribl.com", "URIBL", true, "https://admin.uribl.com/"},
	{"dbl.nordspam.com", "NordSpam DBL", false, "https://www.nordspam.com/"},
}

type blResult struct {
	List   dnsbl
	State  string // clean | listed | unknown
	Answer string
	Reason string
}

// queryDNSBL looks up name (reversed IP or domain) in one list.
func queryDNSBL(ctx context.Context, r *net.Resolver, l dnsbl, name string, domainList bool) blResult {
	res := blResult{List: l, State: "unknown"}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, name+"."+l.Zone)
	if err != nil {
		if isNotFound(err) {
			res.State = "clean"
		} else {
			res.Answer = friendlyDNSErr(err)
		}
		return res
	}
	res.Answer = strings.Join(addrs, ",")
	for _, a := range addrs {
		ip := net.ParseIP(a)
		switch {
		case ip == nil || ip.To4() == nil || ip.To4()[0] != 127:
			res.Answer += " (not a blocklist answer; your DNS may rewrite failed lookups)"
			return res
		case strings.HasPrefix(a, "127.255.255."):
			// Spamhaus: query refused (public resolver / no access).
			res.Answer += " (query refused, e.g. via a public DNS resolver)"
			return res
		case domainList && a == "127.0.0.1":
			res.Answer += " (query refused)"
			return res
		}
	}
	res.State = "listed"
	if txts, err := r.LookupTXT(ctx, name+"."+l.Zone); err == nil && len(txts) > 0 {
		res.Reason = truncate(strings.Join(txts, " "), 160)
	}
	return res
}

func reverseIPv4(ip string) string {
	p := strings.Split(ip, ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0]
}

func runBlacklists(ctx context.Context, rep *report.Report, r *net.Resolver, lists []dnsbl, name string, domainList bool) []blResult {
	out := make([]blResult, len(lists))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for i, l := range lists {
		wg.Add(1)
		go func(i int, l dnsbl) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = queryDNSBL(ctx, r, l, name, domainList)
			rep.Recv("%s.%s → %s %s", name, l.Zone, out[i].State, out[i].Answer)
		}(i, l)
	}
	wg.Wait()
	return out
}

func summarizeBlacklist(st *report.Step, results []blResult, what string) {
	var major, minor, unknown []blResult
	for _, x := range results {
		switch x.State {
		case "listed":
			if x.List.Major {
				major = append(major, x)
			} else {
				minor = append(minor, x)
			}
		case "unknown":
			unknown = append(unknown, x)
		}
	}
	rank := map[string]int{"listed": 0, "unknown": 1, "clean": 2}
	sort.SliceStable(results, func(i, j int) bool { return rank[results[i].State] < rank[results[j].State] })
	for _, x := range results {
		mark := map[string]string{"clean": "✓", "listed": "✗ LISTED", "unknown": "? not checked"}[x.State]
		line := fmt.Sprintf("%s %s (%s)", mark, x.List.Name, x.List.Zone)
		if x.Answer != "" && x.State != "clean" {
			line += " " + x.Answer
		}
		if x.Reason != "" {
			line += " · " + x.Reason
		}
		st.Detail("%s", line)
	}
	names := func(xs []blResult) string {
		var n []string
		for _, x := range xs {
			n = append(n, x.List.Name)
		}
		return strings.Join(n, ", ")
	}
	checked := len(results) - len(unknown)
	note := ""
	if len(unknown) > 0 {
		note = fmt.Sprintf(" %d list(s) couldn't be checked from your DNS (%s).", len(unknown), names(unknown))
	}
	switch {
	case len(major) > 0:
		st.MoreInfo = major[0].List.Site
		st.Set(report.Fail, fmt.Sprintf("Listed on %d major blacklist(s): %s. Many receivers will reject or spam-folder email from this %s.", len(major), names(major), what),
			"Find and fix the cause first (a hacked account or website, an infected computer, or sending to bought lists). Then request removal on each list's website (see More info). If your provider runs this server, tell them."+note)
	case len(minor) > 0:
		st.MoreInfo = minor[0].List.Site
		st.Set(report.Warn, fmt.Sprintf("Listed on %d smaller blacklist(s): %s. Few large providers use these, but some receivers might.", len(minor), names(minor)),
			"Check the listing reason on each list's website and request removal if it's a mistake."+note)
	case checked == 0:
		st.Set(report.Info, "Couldn't check any blacklists from your network.", "Your DNS server may block or rewrite these lookups. Try choosing another DNS server in the form."+note)
	default:
		st.Set(report.OK, fmt.Sprintf("Not listed on any of the %d blacklists checked.", checked), strings.TrimSpace(note))
	}
}

func checkBlacklists(ctx context.Context, rep *report.Report, r *net.Resolver, domain string, mxs []mxHost) {
	for _, t := range mxTargets(mxs) {
		st := rep.BeginIn(CatBlacklist, t.label(), "bl-"+t.IP, "Mail server IP blacklists").Info(DocsURL + "blacklist")
		res := runBlacklists(ctx, rep, r, ipBlacklists, reverseIPv4(t.IP), false)
		summarizeBlacklist(st, res, "server")
	}
	st := rep.BeginIn(CatBlacklist, domain, "bl-domain", "Domain blacklists").Info(DocsURL + "blacklist")
	res := runBlacklists(ctx, rep, r, domainBlacklists, domain, true)
	summarizeBlacklist(st, res, "domain")
}
