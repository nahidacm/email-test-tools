package netcheck

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nahidacm/email-test-tools/internal/report"
)

func checkWeb(ctx context.Context, rep *report.Report, r *net.Resolver, domain string) {
	ips, _ := r.LookupHost(ctx, domain)
	wwwIPs, _ := r.LookupHost(ctx, "www."+domain)
	host := domain
	if len(ips) == 0 && len(wwwIPs) > 0 {
		host = "www." + domain
	}
	st := rep.BeginIn(CatWeb, host, "https", "Website over HTTPS").Info(DocsURL + "website")
	if len(ips) == 0 && len(wwwIPs) == 0 {
		st.Set(report.Info, "No website: the domain has no web address records.", "That's fine if the domain is only used for email.")
		return
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	rep.Sent("GET https://%s/", host)
	resp, err := get(ctx, client, "https://"+host+"/")
	if err != nil {
		st.Detail("%v", err)
		rep.Errf("https://%s/: %v", host, err)
		switch {
		case isCertError(err):
			st.Set(report.Fail, "The website's security certificate is invalid, so browsers show a “Not secure” warning.", "Renew or fix the certificate (e.g. with Let's Encrypt). Details: "+err.Error())
		default:
			st.Set(report.Warn, "The website doesn't load over HTTPS.", "Visitors (and links in your emails) may see an error. Check the web hosting.")
		}
	} else {
		resp.Body.Close()
		st.Detail("%s → %d %s", resp.Request.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
		rep.Recv("%s → %d", resp.Request.URL, resp.StatusCode)
		days := -1
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			days = int(time.Until(c.NotAfter).Hours() / 24)
			st.Detail("Certificate %s, issued by %s, %d days left", c.Subject.CommonName, c.Issuer.CommonName, days)
		}
		switch {
		case resp.StatusCode >= 500:
			st.Set(report.Warn, fmt.Sprintf("The website loads securely but returns a server error (%d).", resp.StatusCode), "Check the web application or hosting.")
		case days >= 0 && days < 14:
			st.Set(report.Warn, fmt.Sprintf("The website works, but its certificate expires in %d day(s).", days), "Renew it soon.")
		default:
			st.Set(report.OK, fmt.Sprintf("The website loads securely (HTTP %d).", resp.StatusCode), "")
		}
	}

	rs := rep.BeginIn(CatWeb, host, "http-redirect", "HTTP sends visitors to HTTPS").Info(DocsURL + "https-redirect")
	noFollow := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rep.Sent("GET http://%s/", host)
	hr, err := get(ctx, noFollow, "http://"+host+"/")
	if err != nil {
		rs.Detail("%v", err)
		rs.Set(report.Info, "The website doesn't answer on plain HTTP (port 80).", "")
		return
	}
	hr.Body.Close()
	loc := hr.Header.Get("Location")
	rs.Detail("http://%s/ → %d %s", host, hr.StatusCode, loc)
	rep.Recv("http://%s/ → %d %s", host, hr.StatusCode, loc)
	if hr.StatusCode >= 300 && hr.StatusCode < 400 && strings.HasPrefix(strings.ToLower(loc), "https://") {
		rs.Set(report.OK, "Yes: plain http:// visits are redirected to the secure site.", "")
	} else {
		rs.Set(report.Warn, "Visitors who type http:// stay on the insecure version of the site.", "Add a permanent (301) redirect from HTTP to HTTPS in your web server or hosting panel.")
	}
}

func get(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "email-test-tools")
	resp, err := c.Do(req)
	if err == nil {
		io.CopyN(io.Discard, resp.Body, 64<<10)
	}
	return resp, err
}

func isCertError(err error) bool {
	var h x509.HostnameError
	var u x509.UnknownAuthorityError
	var i x509.CertificateInvalidError
	return errors.As(err, &h) || errors.As(err, &u) || errors.As(err, &i)
}
