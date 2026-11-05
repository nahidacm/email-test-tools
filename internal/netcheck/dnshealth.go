package netcheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nahidacm/email-test-tools/internal/report"
)

type soaAnswer struct {
	NS     string
	IP     string
	RTT    time.Duration
	AA     bool
	SOA    *dnsmessage.SOAResource
	Rcode  dnsmessage.RCode
	Err    error
	Serial uint32
	// RecursiveOnly: no authoritative answer, but answered when asked to recurse.
	RecursiveOnly bool
}

// querySOA asks one name server directly for the zone's SOA record.
func querySOA(ctx context.Context, ip, zone string, timeout time.Duration, recurse bool) soaAnswer {
	ans := soaAnswer{IP: ip}
	name, err := dnsmessage.NewName(strings.TrimSuffix(zone, ".") + ".")
	if err != nil {
		ans.Err = err
		return ans
	}
	var idb [2]byte
	rand.Read(idb[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(idb[:]), RecursionDesired: recurse},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}},
	}
	pkt, err := msg.Pack()
	if err != nil {
		ans.Err = err
		return ans
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "53"))
	if err != nil {
		ans.Err = err
		return ans
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	t := time.Now()
	if _, err := c.Write(pkt); err != nil {
		ans.Err = err
		return ans
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	ans.RTT = time.Since(t)
	if err != nil {
		ans.Err = err
		return ans
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		ans.Err = err
		return ans
	}
	if h.ID != msg.Header.ID {
		ans.Err = errors.New("reply ID mismatch")
		return ans
	}
	ans.AA, ans.Rcode = h.Authoritative, h.RCode
	if err := p.SkipAllQuestions(); err != nil {
		ans.Err = err
		return ans
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeSOA {
			soa, err := p.SOAResource()
			if err == nil {
				ans.SOA = &soa
				ans.Serial = soa.Serial
			}
			break
		}
		p.SkipAnswer()
	}
	return ans
}

// interceptProbeIP is TEST-NET-1 (RFC 5737): nothing can answer there, so a
// reply means the local network intercepts DNS traffic.
const interceptProbeIP = "192.0.2.1"

func dnsIntercepted(ctx context.Context) bool {
	a := querySOA(ctx, interceptProbeIP, "example.com", 1500*time.Millisecond, true)
	return a.Err == nil
}

func checkDNSHealth(ctx context.Context, rep *report.Report, r *net.Resolver, domain string) {
	// 1. Name servers exist and resolve.
	st := rep.BeginIn(CatDNS, domain, "ns", "Name servers (NS)").Info(DocsURL + "ns")
	rep.Sent("NS %s", domain)
	nss, err := r.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		st.Detail("%v", err)
		st.Set(report.Fail, "No name servers found for this domain.", "The domain may not be registered, or its delegation is broken. Check it at your domain registrar.")
		return
	}
	type nsIP struct{ ns, ip string }
	var targets []nsIP
	var v4 []net.IP
	unresolved := 0
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		ips, err := r.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			unresolved++
			st.Detail("%s → does not resolve", host)
			continue
		}
		var list []string
		for _, ip := range ips {
			list = append(list, ip.String())
			if ip.To4() != nil {
				v4 = append(v4, ip)
			}
		}
		st.Detail("%s → %s", host, strings.Join(list, ", "))
		// Query the first IPv4 address (IPv6 may not be reachable from here).
		for _, ip := range ips {
			if ip.To4() != nil {
				targets = append(targets, nsIP{host, ip.String()})
				break
			}
		}
	}
	switch {
	case unresolved == len(nss):
		st.Set(report.Fail, "The name servers listed for this domain don't exist.", "Fix the NS records at your domain registrar.")
		return
	case unresolved > 0:
		st.Set(report.Warn, fmt.Sprintf("%d of %d name servers can't be found.", unresolved, len(nss)), "Remove or fix the name servers that don't resolve, at your domain registrar.")
	case len(nss) == 1:
		st.Set(report.Warn, "Only one name server. If it goes down, your domain (website and email) stops working.", "Use at least two name servers. DNS providers normally give you two to four.")
	default:
		st.Set(report.OK, fmt.Sprintf("%d name servers are set up.", len(nss)), "")
	}

	// 2. Every name server answers, quickly and authoritatively.
	rs := rep.BeginIn(CatDNS, domain, "ns-respond", "Name servers answer").Info(DocsURL + "ns-respond")
	answers := make([]soaAnswer, len(targets))
	var wg sync.WaitGroup
	var intercepted bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		intercepted = dnsIntercepted(ctx)
		if intercepted {
			rep.Errf("A DNS query to %s (an address where no server can exist) was answered: this network intercepts DNS traffic", interceptProbeIP)
		}
	}()
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t nsIP) {
			defer wg.Done()
			rep.Sent("SOA %s @%s (%s)", domain, t.ns, t.ip)
			a := querySOA(ctx, t.ip, domain, 4*time.Second, false)
			if a.Err == nil && (a.SOA == nil || !a.AA) {
				// Not authoritative. Does it at least answer as a resolver?
				rep.Sent("SOA %s @%s (recursion desired)", domain, t.ns)
				if b := querySOA(ctx, t.ip, domain, 4*time.Second, true); b.Err == nil && b.SOA != nil {
					b.RecursiveOnly = true
					a = b
				}
			}
			a.NS = t.ns
			answers[i] = a
		}(i, t)
	}
	wg.Wait()
	var slow, failed, lame, recursive []string
	for _, a := range answers {
		switch {
		case a.Err != nil:
			failed = append(failed, a.NS)
			rep.Errf("%s: %v", a.NS, a.Err)
			rs.Detail("✗ %s (%s): no answer (%v)", a.NS, a.IP, a.Err)
		case a.RecursiveOnly:
			recursive = append(recursive, a.NS)
			rs.Detail("⚠ %s (%s): no authoritative answer; answers only when asked to recurse (%dms)", a.NS, a.IP, a.RTT.Milliseconds())
		case a.Rcode != dnsmessage.RCodeSuccess || a.SOA == nil:
			lame = append(lame, a.NS)
			rep.Recv("%s: %s, AA=%v", a.NS, a.Rcode, a.AA)
			rs.Detail("✗ %s: answered %s without the zone's SOA", a.NS, strings.TrimPrefix(a.Rcode.String(), "RCode"))
		case !a.AA:
			lame = append(lame, a.NS)
			rs.Detail("⚠ %s: answered but not authoritatively (%dms)", a.NS, a.RTT.Milliseconds())
		default:
			rep.Recv("%s: SOA serial %d, %dms", a.NS, a.Serial, a.RTT.Milliseconds())
			mark := "✓"
			if a.RTT > time.Second {
				slow = append(slow, a.NS)
				mark = "⚠"
			}
			rs.Detail("%s %s (%s): %dms, serial %d", mark, a.NS, a.IP, a.RTT.Milliseconds(), a.Serial)
		}
	}
	switch {
	case intercepted:
		rs.Details = append([]string{"Your network answered a DNS query sent to " + interceptProbeIP + ", an address where no server can exist. The answers below come from your network's own resolver, not from the domain's name servers."}, rs.Details...)
		rs.Set(report.Info, "Couldn't test the name servers directly: your network redirects all DNS traffic to its own resolver.",
			"Common on some ISPs, office firewalls and VPNs. Run the check from another network (for example a phone hotspot or a server) to test the name servers themselves.")
	case len(targets) == 0:
		rs.Set(report.Skip, "No IPv4 name server addresses to test.", "")
	case len(failed) == len(targets):
		rs.Set(report.Fail, "None of the name servers answered.", "Your domain may be unreachable for many visitors. Contact your DNS provider. (If you're on a network that blocks outgoing DNS, try another network.)")
	case len(failed) > 0:
		rs.Set(report.Warn, fmt.Sprintf("At least one name server failed to respond in a timely manner (%s).", strings.Join(failed, ", ")),
			"Resolvers retry other servers, so things still work, but slower and less reliably. Ask your DNS provider to fix or remove that server.")
	case len(recursive) > 0:
		rs.Set(report.Warn, fmt.Sprintf("Name servers don't answer authoritatively for this domain (%s). They only answer as general-purpose resolvers.", strings.Join(recursive, ", ")),
			"Other resolvers may fail to look up your domain at times (a “lame delegation”). Ask your DNS provider to host the zone authoritatively on these servers.")
	case len(lame) > 0:
		rs.Set(report.Warn, fmt.Sprintf("Some name servers don't hold this domain's records (%s): a “lame delegation”.", strings.Join(lame, ", ")),
			"Remove those servers from the domain's NS list at the registrar, or add the zone to them.")
	case len(slow) > 0:
		rs.Set(report.Warn, fmt.Sprintf("Some name servers are slow to answer (%s, over 1 second).", strings.Join(slow, ", ")), "Slow DNS delays every email and web request. Consider a faster DNS provider.")
	default:
		rs.Set(report.OK, fmt.Sprintf("All %d name servers answered quickly and authoritatively.", len(targets)), "")
	}

	// 3. Network diversity.
	if len(v4) >= 2 {
		ds := rep.BeginIn(CatDNS, domain, "ns-subnet", "Name servers on different networks").Info(DocsURL + "ns-subnet")
		nets := map[string]bool{}
		for _, ip := range v4 {
			nets[ip.Mask(net.CIDRMask(24, 32)).String()] = true
		}
		for n := range nets {
			ds.Detail("%s/24", n)
		}
		if len(nets) == 1 {
			ds.Set(report.Warn, "All name servers are on the same subnet, so one network outage can take them all down.",
				"RFC 2182 recommends name servers in different networks or locations. Ask your DNS provider, or add a secondary DNS service.")
		} else {
			ds.Set(report.OK, fmt.Sprintf("Name servers are spread over %d networks.", len(nets)), "")
		}
	}

	// 4 & 5. SOA consistency and values.
	var good []soaAnswer
	for _, a := range answers {
		if a.SOA != nil {
			good = append(good, a)
		}
	}
	if len(good) == 0 {
		return
	}
	if len(good) > 1 && !intercepted {
		ss := rep.BeginIn(CatDNS, domain, "soa-serial", "Name servers are in sync").Info(DocsURL + "soa-serial")
		// Domains using several DNS providers have one SOA per provider;
		// only servers that name the same primary should share a serial.
		byPrimary := map[string]map[uint32][]string{}
		for _, a := range good {
			pm := strings.ToLower(a.SOA.NS.String())
			if byPrimary[pm] == nil {
				byPrimary[pm] = map[uint32][]string{}
			}
			byPrimary[pm][a.Serial] = append(byPrimary[pm][a.Serial], a.NS)
		}
		serials := map[uint32][]string{}
		mismatch := false
		for _, m := range byPrimary {
			if len(m) > 1 {
				mismatch = true
			}
			for k, v := range m {
				serials[k] = append(serials[k], v...)
			}
		}
		if len(byPrimary) > 1 {
			ss.Detail("This domain uses %d DNS providers (different SOA primaries); serials are compared within each provider.", len(byPrimary))
		}
		keys := make([]uint32, 0, len(serials))
		for k := range serials {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			ss.Detail("serial %d: %s", k, strings.Join(serials[k], ", "))
		}
		if mismatch {
			ss.Set(report.Warn, "Name servers have different versions of your DNS records (serial numbers differ).",
				"Recent changes haven't reached every server yet. If this lasts more than a few hours, zone transfers between the servers are broken; contact your DNS provider.")
		} else {
			msg := "All name servers have the same version of your DNS records."
			if len(byPrimary) > 1 {
				msg = fmt.Sprintf("Name servers are in sync within each of the %d DNS providers.", len(byPrimary))
			}
			ss.Set(report.OK, msg, "")
		}
	}

	soa := good[0].SOA
	vs := rep.BeginIn(CatDNS, domain, "soa", "Zone settings (SOA)").Info(DocsURL + "soa-values")
	vs.Detail("Primary: %s  Contact: %s", strings.TrimSuffix(soa.NS.String(), "."), strings.TrimSuffix(soa.MBox.String(), "."))
	vs.Detail("Serial %d · Refresh %d · Retry %d · Expire %d · Minimum TTL %d", soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.MinTTL)
	var out []string
	check := func(name string, v, lo, hi uint32, why string) {
		if v < lo || v > hi {
			out = append(out, fmt.Sprintf("SOA %s value (%d) is out of the recommended range %d–%d. %s", name, v, lo, hi, why))
		}
	}
	// Ranges follow RFC 1912 §2.2 and RIPE-203.
	check("Refresh", soa.Refresh, 1200, 43200, "It controls how often secondary servers check for changes.")
	check("Retry", soa.Retry, 120, 7200, "It controls how soon secondaries retry after a failed check.")
	check("Expire", soa.Expire, 1209600, 2419200, "It's how long secondaries keep answering if the primary is unreachable; 2–4 weeks is recommended.")
	check("Minimum TTL", soa.MinTTL, 300, 86400, "It's how long “does not exist” answers are cached.")
	if soa.Retry >= soa.Refresh {
		out = append(out, "SOA Retry should be lower than Refresh.")
	}
	vs.Details = append(vs.Details, out...)
	if len(out) > 0 {
		vs.Set(report.Warn, fmt.Sprintf("%d SOA value(s) are outside the recommended range.", len(out)), strings.Join(out, " ")+" These are set by your DNS provider; minor, but worth asking them about.")
	} else {
		vs.Set(report.OK, "Zone timing values are within recommended ranges.", "")
	}
}
