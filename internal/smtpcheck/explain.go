package smtpcheck

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
)

func randRead(b []byte) { rand.Read(b) }

type phase int

const (
	phaseAuth phase = iota
	phaseFrom
	phaseRcpt
	phaseData
)

// provider holds tips for well-known email services.
type provider struct {
	Name     string
	AuthHint string
	FromHint string
	RcptHint string
}

func detectProvider(host string) provider {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "gmail") || strings.Contains(h, "googlemail") || strings.HasSuffix(h, "google.com"):
		return provider{Name: "Google / Gmail",
			AuthHint: "Gmail doesn't accept your normal password here. Turn on 2-Step Verification for the Google account, then create an “App password” (Google Account → Security → App passwords) and use that 16-character code as the password.",
			FromHint: "Gmail only lets you send as your own address, or as an alias added under Gmail Settings → Accounts → “Send mail as”."}
	case strings.Contains(h, "office365") || strings.Contains(h, "outlook") || strings.Contains(h, "hotmail") || strings.Contains(h, "live.com"):
		return provider{Name: "Microsoft 365 / Outlook",
			AuthHint: "Microsoft often turns off password login for SMTP. An admin must enable “Authenticated SMTP” for this mailbox (Microsoft 365 admin center → Users → Mail → Manage email apps). Accounts with MFA need an app password, or Security Defaults may block it entirely.",
			FromHint: "Microsoft 365 only lets you send as the signed-in mailbox, unless you've been given “Send As” permission for another address."}
	case strings.Contains(h, "amazonaws.com"):
		return provider{Name: "Amazon SES",
			AuthHint: "Amazon SES needs special SMTP credentials (SES console → SMTP settings → Create SMTP credentials), not your AWS access keys or console password. The credentials also only work in the region they were created for.",
			FromHint: "In Amazon SES, the sender address or its domain must be verified in the SES console for this region.",
			RcptHint: "If your SES account is still in the “sandbox”, you can only send to verified addresses. Verify the recipient, or request production access."}
	case strings.Contains(h, "sendgrid"):
		return provider{Name: "SendGrid",
			AuthHint: "For SendGrid the username must be literally “apikey”, and the password is your API key (it starts with “SG.”).",
			FromHint: "SendGrid requires a verified Sender Identity: verify the single sender address or authenticate the whole domain."}
	case strings.Contains(h, "mailgun"):
		return provider{Name: "Mailgun",
			AuthHint: "Use the SMTP credentials from Mailgun → Sending → Domain settings → SMTP credentials (often postmaster@your-domain), not your Mailgun login.",
			RcptHint: "Mailgun sandbox domains can only send to “authorized recipients” you've added in the dashboard."}
	case strings.Contains(h, "yahoo"):
		return provider{Name: "Yahoo",
			AuthHint: "Yahoo requires an app password: Account Security → Generate app password."}
	case strings.Contains(h, "zoho"):
		return provider{Name: "Zoho",
			AuthHint: "If two-factor authentication is on, create an application-specific password in Zoho Accounts → Security. Also check that the server matches your data center (smtp.zoho.com vs smtp.zoho.eu, .in, …)."}
	case strings.Contains(h, "icloud") || strings.Contains(h, "me.com"):
		return provider{Name: "iCloud",
			AuthHint: "iCloud Mail needs an app-specific password from appleid.apple.com → Sign-In and Security."}
	}
	return provider{}
}

// explainNetErr turns a dial error into words.
func explainNetErr(err error, port int) (summary, hint string) {
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return "Could not connect.", ""
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("The server is reachable, but nothing is accepting connections on port %d.", port),
			"Double-check the port number. Common email ports are 587 (STARTTLS), 465 (SSL/TLS) and 25. Your provider's settings page lists the right one."
	case isTimeout(err):
		h := fmt.Sprintf("Something between you and the server is silently blocking port %d: usually a firewall, your internet provider, or a cloud host. ", port)
		if port == 25 {
			h += "Port 25 is blocked by most home internet providers and cloud platforms (AWS, Google Cloud, Azure, DigitalOcean…). Try port 587 or 465 instead."
		} else {
			h += "Use the Port Check tool to compare ports, or try from a different network (for example a phone hotspot) to see if your network is the cause."
		}
		return "No response: the connection attempt timed out.", h
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return "Your computer has no route to that server.",
			"Check your internet connection. If the server has only an IPv6 address, your network may not support IPv6."
	case errors.As(err, &dnsErr):
		return "We couldn't look up the server address.", "Check the server name for typos."
	}
	return "The connection failed: " + err.Error(), "Check your internet connection and firewall settings."
}

func explainTLSErr(err error, req Request) (summary, hint string) {
	msg := err.Error()
	var hostErr x509.HostnameError
	var unkAuth x509.UnknownAuthorityError
	var certInv x509.CertificateInvalidError
	var recErr tls.RecordHeaderError
	switch {
	case errors.As(err, &recErr) || strings.Contains(msg, "first record does not look like a TLS handshake"):
		return "this port doesn't use SSL/TLS from the start.",
			fmt.Sprintf("Port %d expects a plain connection that is upgraded later. Change Security to “STARTTLS”.", req.Port)
	case errors.As(err, &hostErr):
		return "the server's certificate is for a different name.",
			fmt.Sprintf("The certificate doesn't cover “%s”. Use the exact server name your provider documents (the certificate covers: %s). On shared hosting this often means using the hosting company's server name instead of mail.yourdomain.com.",
				req.Host, strings.Join(hostErr.Certificate.DNSNames, ", "))
	case errors.As(err, &unkAuth):
		return "the server's certificate isn't from a trusted authority (self-signed or private CA).",
			"If this is your own or an internal server, you can tick “Don't verify certificate” under Advanced options to continue testing. Real apps should use a properly issued certificate (e.g. Let's Encrypt)."
	case errors.As(err, &certInv):
		if certInv.Reason == x509.Expired {
			return "the server's security certificate has expired.",
				"The server administrator must renew the certificate. Until then, email apps will show security errors."
		}
		return "the server's certificate is invalid (" + certInv.Detail + ").", "Ask the server administrator to check the certificate."
	case strings.Contains(msg, "protocol version") || strings.Contains(msg, "no supported versions"):
		return "the server only supports outdated encryption.", "The server uses old TLS versions that modern software refuses. The server needs updating."
	case isTimeout(err):
		return "the secure handshake timed out.",
			"If you're on port 587 or 25, the server is probably waiting for plain text: change Security to “STARTTLS”."
	case errors.Is(err, io.EOF) || strings.Contains(msg, "connection reset"):
		return "the server hung up during the secure handshake.",
			"The security setting probably doesn't match this port. Try STARTTLS for 587/25 and SSL/TLS for 465."
	}
	return msg, "Check that the Security option matches the port: STARTTLS for 587/25, SSL/TLS for 465."
}

func explainSMTP(err error, ph phase, p provider) (summary, hint string) {
	var se *smtpError
	if !errors.As(err, &se) {
		if isTimeout(err) {
			return "The server stopped responding.", "The server took too long to answer. Try again, or raise the timeout under Advanced options."
		}
		return "The connection was lost: " + err.Error(), "The server closed the connection. It may be rate-limiting or blocking you; wait a little and try again."
	}
	m := strings.ToLower(se.Msg)
	code, enh := se.Code, se.Enhanced
	addProv := func(h, ph string) string {
		if ph == "" {
			return h
		}
		if h == "" {
			return ph
		}
		return h + " " + ph
	}

	// Temporary failures (4xx) are worth calling out regardless of phase.
	if code/100 == 4 {
		switch {
		case code == 421:
			return fmt.Sprintf("The server is temporarily refusing service (%d).", code), "The server is busy or limiting connections. Wait a few minutes and try again."
		case code == 452 || strings.Contains(m, "quota") || strings.Contains(m, "limit"):
			return fmt.Sprintf("A temporary limit was reached (%d): %s", code, se.Msg), "You may have hit a sending limit or the mailbox is full. Try again later."
		default:
			return fmt.Sprintf("Temporary problem (%d): %s", code, se.Msg), "This is usually temporary (for example greylisting). Wait a few minutes and try again."
		}
	}

	switch ph {
	case phaseAuth:
		switch {
		case code == 534 && strings.Contains(m, "application-specific"), code == 534 && enh == "5.7.9":
			return "The provider wants an app password, not your normal password.", addProv("", p.AuthHint)
		case code == 535 && strings.Contains(m, "5.7.139"), strings.Contains(m, "smtpclientauthentication is disabled"):
			return "Password login for SMTP is turned off for this mailbox.", addProv("", p.AuthHint)
		case code == 535, enh == "5.7.8", code == 454 && strings.Contains(m, "auth"):
			return "The username or password was rejected.", addProv("Re-type both carefully. The username is usually your full email address.", p.AuthHint)
		case code == 530 || code == 538:
			return "The server requires encryption before you log in.", "Use STARTTLS or SSL/TLS."
		case code == 534:
			return "The server needs a stronger login method or extra account setup.", addProv("", p.AuthHint)
		case code == 504:
			return "The server doesn't accept this login method.", ""
		}
		return fmt.Sprintf("Login failed (%d): %s", code, se.Msg), addProv("", p.AuthHint)

	case phaseFrom:
		switch {
		case code == 530 || strings.Contains(m, "authentication required") || enh == "5.7.0" && strings.Contains(m, "auth"):
			return "The server needs you to log in before sending.", "Fill in the username and password."
		case code == 553 || code == 550 || code == 551 || code == 555:
			return fmt.Sprintf("The server won't let you send as this address (%d): %s", code, se.Msg),
				addProv("The sender address usually has to match the account you logged in with, or a verified alias/domain.", p.FromHint)
		}
		return fmt.Sprintf("The sender address was refused (%d): %s", code, se.Msg), p.FromHint

	case phaseRcpt:
		switch {
		case strings.Contains(m, "relay") || enh == "5.7.1" && (strings.Contains(m, "relay") || strings.Contains(m, "not permitted")):
			return "The server won't forward mail to outside addresses for you (“relaying denied”).",
				"Log in with a username and password. An unauthenticated server only accepts mail for its own domains."
		case code == 530:
			return "The server needs you to log in first.", "Fill in the username and password."
		case enh == "5.1.1" || strings.Contains(m, "user unknown") || strings.Contains(m, "does not exist") || strings.Contains(m, "no such user"):
			return "The recipient address doesn't exist on the receiving server.", "Check the recipient address for typos."
		case strings.Contains(m, "not verified") || strings.Contains(m, "sandbox"):
			return "The recipient isn't allowed yet: " + se.Msg, p.RcptHint
		case enh == "5.7.1" || code == 554:
			return fmt.Sprintf("The recipient was refused by policy (%d): %s", code, se.Msg), addProv("The server's rules don't allow this recipient.", p.RcptHint)
		}
		return fmt.Sprintf("Recipient refused (%d): %s", code, se.Msg), p.RcptHint

	case phaseData:
		switch {
		case strings.Contains(m, "spam") || strings.Contains(m, "content") || strings.Contains(m, "policy"):
			return "The server rejected the message content as unwanted.", "Try a plain, short message. The server's spam filter didn't like this one."
		case code == 552 || strings.Contains(m, "size"):
			return "The message is too large.", ""
		case strings.Contains(m, "not verified"):
			return "Rejected: " + se.Msg, addProv(p.FromHint, p.RcptHint)
		case strings.Contains(m, "dmarc") || strings.Contains(m, "spf") || strings.Contains(m, "dkim"):
			return "Rejected because the sender's domain failed authentication checks.", "Use the Domain Health tool on the sender's domain to check SPF, DKIM and DMARC."
		}
		return fmt.Sprintf("The message was rejected (%d): %s", code, se.Msg), ""
	}
	return se.Error(), ""
}
