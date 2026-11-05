// Package tlsinfo turns a TLS connection state into JSON-friendly facts.
package tlsinfo

import (
	"crypto/tls"
	"crypto/x509"
	"math"
	"time"
)

type Cert struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	DNSNames     []string  `json:"dnsNames,omitempty"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	DaysLeft     int       `json:"daysLeft"`
	SerialNumber string    `json:"serial"`
	SigAlgorithm string    `json:"sigAlgorithm"`
	SelfSigned   bool      `json:"selfSigned"`
}

type Info struct {
	Version       string `json:"version"`
	CipherSuite   string `json:"cipherSuite"`
	ServerName    string `json:"serverName"`
	NameMatches   bool   `json:"nameMatches"`
	Trusted       bool   `json:"trusted"`
	TrustError    string `json:"trustError,omitempty"`
	Chain         []Cert `json:"chain"`
	OCSPStapled   bool   `json:"ocspStapled"`
	NegotiatedALP string `json:"alpn,omitempty"`
}

func FromState(cs tls.ConnectionState, serverName string) *Info {
	info := &Info{
		Version:       tls.VersionName(cs.Version),
		CipherSuite:   tls.CipherSuiteName(cs.CipherSuite),
		ServerName:    serverName,
		OCSPStapled:   len(cs.OCSPResponse) > 0,
		NegotiatedALP: cs.NegotiatedProtocol,
		Chain:         []Cert{},
	}
	for _, c := range cs.PeerCertificates {
		info.Chain = append(info.Chain, FromCert(c))
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.NameMatches = leaf.VerifyHostname(serverName) == nil
		// Verify independently so we can report trust even when verification was skipped.
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: inter})
		info.Trusted = err == nil
		if err != nil {
			info.TrustError = err.Error()
		}
	}
	return info
}

func FromCert(c *x509.Certificate) Cert {
	return Cert{
		Subject:      c.Subject.CommonName,
		Issuer:       nameOr(c.Issuer.CommonName, c.Issuer.String()),
		DNSNames:     c.DNSNames,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		DaysLeft:     int(math.Floor(time.Until(c.NotAfter).Hours() / 24)),
		SerialNumber: c.SerialNumber.Text(16),
		SigAlgorithm: c.SignatureAlgorithm.String(),
		SelfSigned:   c.Subject.String() == c.Issuer.String(),
	}
}

func nameOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
