package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type TLSScanner struct{}

func (t *TLSScanner) Name() string {
	return "tls"
}

func (t *TLSScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	parsed, err := url.Parse(u.URL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		f := model.NewFinding(
			"tls",
			"tls_handshake_issue",
			"TLS handshake failed",
			"Server TLS handshake failed. This can indicate certificate or protocol issues.",
			"Medium",
			standards.A04CryptographicFailures,
			u.URL,
			err.Error(),
			"Check certificate chain and TLS configuration.",
			standards.A04URL,
		)
		f.ID = buildID("TLS", u.URL, 0)
		return []model.Finding{f}
	}
	conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: false, ServerName: parsed.Hostname()})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		f := model.NewFinding(
			"tls",
			"tls_handshake_issue",
			"TLS handshake failed",
			"Server TLS handshake failed. This can indicate certificate or protocol issues.",
			"Medium",
			standards.A04CryptographicFailures,
			u.URL,
			err.Error(),
			"Check certificate chain and TLS configuration.",
			standards.A04URL,
		)
		f.ID = buildID("TLS", u.URL, 0)
		return []model.Finding{f}
	}

	state := conn.ConnectionState()
	findings := []model.Finding{}

	if state.Version < tls.VersionTLS12 {
		f := model.NewFinding(
			"tls",
			"deprecated_tls_version",
			"Deprecated TLS version negotiated",
			"The server negotiated a TLS version older than 1.2.",
			"High",
			standards.A04CryptographicFailures,
			u.URL,
			fmt.Sprintf("TLS version: 0x%x", state.Version),
			"Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
			"https://datatracker.ietf.org/doc/rfc8996/",
		)
		f.ID = buildID("TLS", u.URL, len(findings))
		findings = append(findings, f)
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft < 0 {
			f := model.NewFinding(
				"tls",
				"expired_certificate",
				"TLS certificate expired",
				"The server certificate has expired.",
				"High",
				standards.A04CryptographicFailures,
				u.URL,
				"Certificate NotAfter: "+cert.NotAfter.Format(time.RFC3339),
				"Renew and deploy a valid certificate immediately.",
				standards.A04URL,
			)
			f.ID = buildID("TLS", u.URL, len(findings))
			findings = append(findings, f)
		} else if daysLeft <= 30 {
			f := model.NewFinding(
				"tls",
				"certificate_near_expiry",
				"TLS certificate near expiration",
				"The certificate is close to expiration and may cause outage or trust warnings soon.",
				"Low",
				standards.A02SecurityMisconfiguration,
				u.URL,
				fmt.Sprintf("Certificate expires in %d days", daysLeft),
				"Schedule certificate renewal before expiry.",
				standards.A02URL,
			)
			f.ID = buildID("TLS", u.URL, len(findings))
			findings = append(findings, f)
		}
	}

	return findings
}
