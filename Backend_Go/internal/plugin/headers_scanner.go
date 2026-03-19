package plugin

// ─── HeaderScanner — HTTP Security Headers (A02/A06:2025) ────────────────────
//
// Receives: URLInfo (one URL per call)
// Does:     1 GET request → inspects HTTP response headers
// Returns:  []Finding  (0–7 findings per URL depending on missing headers)
//
// Checks performed and their OWASP/CWE mapping:
//   Header                   | Missing/Weak → OWASP    | CWE
//   ─────────────────────────────────────────────────────────
//   X-Frame-Options          | Missing      → A06:2025  | CWE-1021
//   X-Content-Type-Options   | Missing      → A06:2025  | CWE-693
//   Content-Security-Policy  | Missing      → A06:2025  | CWE-693
//   Content-Security-Policy  | unsafe-inline→ A06:2025  | CWE-693, CWE-79
//   Strict-Transport-Security| Missing*     → A06:2025  | CWE-693   (*HTTPS only)
//   Referrer-Policy          | Missing      → A06:2025  | CWE-693
//   Permissions-Policy       | Missing      → A06:2025  | CWE-693
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"log"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type HeaderScanner struct{}

func (h *HeaderScanner) Name() string {
	return "headers"
}

func (h *HeaderScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, u.URL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("[HeaderScanner] error:", err)
		return nil
	}
	defer resp.Body.Close()

	findings := []model.Finding{}

	if resp.Header.Get("X-Frame-Options") == "" {
		f := model.NewFinding(
			"headers",
			"missing_security_header",
			"Missing X-Frame-Options",
			"Response does not contain X-Frame-Options header, increasing clickjacking risk.",
			"Medium",
			standards.A06InsecureDesign,
			u.URL,
			"X-Frame-Options header not found",
			"Set X-Frame-Options to DENY or SAMEORIGIN.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-1021"}
		findings = append(findings, f)
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		f := model.NewFinding(
			"headers",
			"missing_security_header",
			"Missing X-Content-Type-Options",
			"Response does not contain X-Content-Type-Options header.",
			"Low",
			standards.A06InsecureDesign,
			u.URL,
			"X-Content-Type-Options header not found",
			"Set X-Content-Type-Options to nosniff.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-693"}
		findings = append(findings, f)
	}

	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		f := model.NewFinding(
			"headers",
			"missing_security_header",
			"Missing Content-Security-Policy",
			"Content-Security-Policy header is missing, reducing protection against script injection.",
			"Medium",
			standards.A06InsecureDesign,
			u.URL,
			"Content-Security-Policy header not found",
			"Define a restrictive Content-Security-Policy for scripts and objects.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-693"}
		findings = append(findings, f)
	} else if strings.Contains(strings.ToLower(csp), "unsafe-inline") {
		f := model.NewFinding(
			"headers",
			"weak_security_header",
			"Weak Content-Security-Policy",
			"Content-Security-Policy contains unsafe-inline which weakens XSS protections.",
			"Low",
			standards.A06InsecureDesign,
			u.URL,
			"CSP contains unsafe-inline",
			"Avoid unsafe-inline and adopt nonce/hash based CSP.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-693", "CWE-79"}
		findings = append(findings, f)
	}

	if strings.HasPrefix(strings.ToLower(u.URL), "https://") {
		if resp.Header.Get("Strict-Transport-Security") == "" {
			f := model.NewFinding(
				"headers",
				"missing_security_header",
				"Missing Strict-Transport-Security (HSTS)",
				"Response does not include Strict-Transport-Security header, allowing protocol downgrade attacks.",
				"High",
				standards.A06InsecureDesign,
				u.URL,
				"Strict-Transport-Security header not found",
				"Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
				standards.A06URL,
			)
			f.CWEIDs = []string{"CWE-693"}
			findings = append(findings, f)
		}
	}

	if resp.Header.Get("Referrer-Policy") == "" {
		f := model.NewFinding(
			"headers",
			"missing_security_header",
			"Missing Referrer-Policy",
			"Referrer-Policy header is absent, potentially leaking URL information to third parties.",
			"Low",
			standards.A06InsecureDesign,
			u.URL,
			"Referrer-Policy header not found",
			"Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-693"}
		findings = append(findings, f)
	}

	if resp.Header.Get("Permissions-Policy") == "" {
		f := model.NewFinding(
			"headers",
			"missing_security_header",
			"Missing Permissions-Policy",
			"Permissions-Policy header is absent, leaving browser features unrestricted.",
			"Low",
			standards.A06InsecureDesign,
			u.URL,
			"Permissions-Policy header not found",
			"Set Permissions-Policy to restrict camera, microphone, geolocation, and other browser features.",
			standards.A06URL,
		)
		f.CWEIDs = []string{"CWE-693"}
		findings = append(findings, f)
	}

	for i := range findings {
		findings[i].ID = buildID("HDR", u.URL, i)
	}

	return findings
}
