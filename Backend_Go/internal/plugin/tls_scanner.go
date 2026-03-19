package plugin

// ─── TLSScanner — TLS/Certificate Issues (A04/A07:2025) ──────────────────────
//
// Receives: URLInfo (HTTPS URLs only — returns nil for HTTP)
// Does:     Raw TCP dial → TLS handshake → inspect connection state
// Returns:  []Finding  (0–3 findings per HTTPS URL)
//
// Checks performed:
//   1. TCP connection failure   → Finding (Medium, A07, CWE-295)
//      Cannot even reach the TLS port — possible network or config issue.
//
//   2. TLS handshake failure    → Finding (Medium, A07, CWE-295)
//      Certificate rejected, wrong hostname, or unsupported cipher.
//
//   3. Deprecated TLS version   → Finding (High, A04, CWE-327)
//      Server negotiated TLS < 1.2 (i.e. TLS 1.0 or 1.1, both deprecated).
//
//   4. Expired certificate      → Finding (High, A07, CWE-298)
//      cert.NotAfter is in the past.
//
//   4b. Near-expiry certificate → Finding (Low, A07, CWE-298)
//      cert.NotAfter is within 30 days.
//
// Note: TLS check uses a raw net.Dialer + tls.Client (not http.Client)
// so it inspects the actual negotiated version and certificate chain directly.
//
// ─────────────────────────────────────────────────────────────────────────────

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
			standards.A07AuthFailures,
			u.URL,
			err.Error(),
			"Check certificate chain and TLS configuration.",
			standards.A07URL,
		)
		f.ID = buildID("TLS", u.URL, 0)
		f.CWEIDs = []string{"CWE-295"}
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
			standards.A07AuthFailures,
			u.URL,
			err.Error(),
			"Check certificate chain and TLS configuration.",
			standards.A07URL,
		)
		f.ID = buildID("TLS", u.URL, 0)
		f.CWEIDs = []string{"CWE-295"}
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
		f.CWEIDs = []string{"CWE-327"}
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
				standards.A07AuthFailures,
				u.URL,
				"Certificate NotAfter: "+cert.NotAfter.Format(time.RFC3339),
				"Renew and deploy a valid certificate immediately.",
				standards.A07URL,
			)
			f.ID = buildID("TLS", u.URL, len(findings))
			f.CWEIDs = []string{"CWE-298"}
			findings = append(findings, f)
		} else if daysLeft <= 30 {
			f := model.NewFinding(
				"tls",
				"certificate_near_expiry",
				"TLS certificate near expiration",
				"The certificate is close to expiration and may cause outage or trust warnings soon.",
				"Low",
				standards.A07AuthFailures,
				u.URL,
				fmt.Sprintf("Certificate expires in %d days", daysLeft),
				"Schedule certificate renewal before expiry.",
				standards.A07URL,
			)
			f.ID = buildID("TLS", u.URL, len(findings))
			f.CWEIDs = []string{"CWE-298"}
			findings = append(findings, f)
		}
	}

	return findings
}
