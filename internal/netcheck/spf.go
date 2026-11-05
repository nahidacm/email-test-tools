package netcheck

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// spfSyntax validates an SPF record (RFC 7208 §12) and returns problems
// (record is broken) and warnings (works, but should be improved).
func spfSyntax(rec string) (problems, warnings []string) {
	fields := strings.Fields(rec)
	if len(fields) == 0 {
		return []string{"The record is empty."}, nil
	}
	if !strings.EqualFold(fields[0], "v=spf1") {
		if strings.HasPrefix(strings.ToLower(fields[0]), "v=spf1") {
			return []string{fmt.Sprintf(
				"The record begins “%s”, with no space after v=spf1. This usually happens when the record is entered as several quoted pieces (\"v=spf1\" \"include:…\" \"-all\"): DNS joins the pieces with nothing in between. Put a space at the end of each piece, or enter the whole record as one piece.",
				truncate(fields[0], 40))}, nil
		}
		return []string{"The record must start with “v=spf1”."}, nil
	}

	allSeen, redirect, exp := 0, 0, 0
	for i, term := range fields[1:] {
		t := strings.ToLower(term)
		if allSeen > 0 && !strings.Contains(t, "=") {
			warnings = append(warnings, fmt.Sprintf("“%s” comes after “all” and is ignored.", term))
		}
		// Modifier: name=value (name has no ':' or '/').
		if eq := strings.IndexByte(t, '='); eq > 0 && !strings.ContainsAny(t[:eq], ":/") {
			name, val := t[:eq], t[eq+1:]
			switch name {
			case "redirect":
				redirect++
				if !validDomainSpec(val) {
					problems = append(problems, fmt.Sprintf("“%s” needs a valid domain.", term))
				}
			case "exp":
				exp++
			default:
				if !isSPFName(name) {
					problems = append(problems, fmt.Sprintf("“%s” is not a valid SPF term.", term))
				}
			}
			continue
		}
		mech := strings.TrimLeft(t, "+-~?")
		if len(t)-len(mech) > 1 {
			problems = append(problems, fmt.Sprintf("“%s” has more than one qualifier (+ - ~ ?).", term))
		}
		name, arg := mech, ""
		if j := strings.IndexAny(mech, ":/"); j >= 0 {
			name, arg = mech[:j], mech[j:]
		}
		switch name {
		case "all":
			allSeen++
			if arg != "" {
				problems = append(problems, fmt.Sprintf("“%s”: “all” takes no value.", term))
			}
		case "include", "exists":
			if !strings.HasPrefix(arg, ":") || !validDomainSpec(arg[1:]) {
				problems = append(problems, fmt.Sprintf("“%s” needs a domain, e.g. %s:_spf.example.com.", term, name))
			}
		case "a", "mx":
			if p := spfDomainCIDR(arg); p != "" {
				problems = append(problems, fmt.Sprintf("“%s”: %s", term, p))
			}
		case "ptr":
			warnings = append(warnings, "“ptr” is deprecated (RFC 7208) and slow; many receivers ignore it. Remove it.")
			if arg != "" && (!strings.HasPrefix(arg, ":") || !validDomainSpec(arg[1:])) {
				problems = append(problems, fmt.Sprintf("“%s” has an invalid domain.", term))
			}
		case "ip4", "ip6":
			if !strings.HasPrefix(arg, ":") {
				problems = append(problems, fmt.Sprintf("“%s” needs an address, e.g. %s:192.0.2.10.", term, name))
				break
			}
			if p := spfIP(name, arg[1:]); p != "" {
				problems = append(problems, fmt.Sprintf("“%s”: %s", term, p))
			}
		default:
			hint := ""
			if i == 0 && strings.HasPrefix(t, "include") {
				hint = " Did you forget the colon (include:domain)?"
			}
			problems = append(problems, fmt.Sprintf("Unknown term “%s”.%s", term, hint))
		}
	}
	if allSeen > 1 {
		problems = append(problems, "“all” appears more than once.")
	}
	if redirect > 1 || exp > 1 {
		problems = append(problems, "“redirect=” and “exp=” may each appear only once.")
	}
	if redirect > 0 && allSeen > 0 {
		warnings = append(warnings, "“redirect=” is ignored because the record also has “all”.")
	}
	return problems, warnings
}

func isSPFName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// validDomainSpec accepts domains and SPF macros (%{...}).
func validDomainSpec(d string) bool {
	if strings.Contains(d, "%{") {
		return true
	}
	d = strings.TrimSuffix(d, ".")
	if !strings.Contains(d, ".") || strings.ContainsAny(d, " /:@") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
	}
	return true
}

// spfDomainCIDR validates the optional ":domain/cidr//cidr6" part of a / mx.
func spfDomainCIDR(arg string) string {
	if arg == "" {
		return ""
	}
	dom, cidr := arg, ""
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		dom, cidr = arg[:i], arg[i:]
	}
	if dom != "" {
		if !strings.HasPrefix(dom, ":") || !validDomainSpec(dom[1:]) {
			return "invalid domain."
		}
	}
	if cidr != "" {
		v4, v6, _ := strings.Cut(strings.TrimPrefix(cidr, "/"), "//")
		if strings.HasPrefix(cidr, "//") {
			v4, v6 = "", strings.TrimPrefix(cidr, "//")
		}
		if v4 != "" {
			if n, err := strconv.Atoi(v4); err != nil || n < 0 || n > 32 {
				return "invalid IPv4 prefix length."
			}
		}
		if v6 != "" {
			if n, err := strconv.Atoi(v6); err != nil || n < 0 || n > 128 {
				return "invalid IPv6 prefix length."
			}
		}
	}
	return ""
}

func spfIP(kind, v string) string {
	addr, bits, hasBits := strings.Cut(v, "/")
	ip := net.ParseIP(addr)
	if ip == nil {
		return "not a valid IP address."
	}
	is4 := ip.To4() != nil && !strings.Contains(addr, ":")
	if kind == "ip4" && !is4 {
		return "ip4 needs an IPv4 address."
	}
	if kind == "ip6" && is4 {
		return "ip6 needs an IPv6 address (use ip4: for IPv4)."
	}
	if hasBits {
		max := 32
		if kind == "ip6" {
			max = 128
		}
		if n, err := strconv.Atoi(bits); err != nil || n < 0 || n > max {
			return "invalid prefix length."
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
