package plugin

// ─── XSSScanner — Reflected XSS Detection (A05:2025) ─────────────────────────
//
// Receives: URLInfo — only processes URLs that have query parameters.
//           URLs without query params are skipped immediately (return nil).
// Does:     Nonce-based reflection probing per query parameter.
// Returns:  []Finding  (one per vulnerable parameter, max one payload tested)
//
// Algorithm for each query parameter:
//   1. Generate a random 8-char hex nonce (shared for the entire Scan call).
//   2. Try each of 4 payload templates (in order):
//        html_body : <script>/*NONCE*/</script>
//        html_attr : "><img src=x onerror=/*NONCE*/>
//        js_context: ';/*NONCE*/
//        reflection: va-NONCE-probe    (plain string, catches text reflection)
//   3. Replace %NONCE% placeholder → send GET request with payload as param value.
//   4. If the nonce string appears anywhere in the response body → reflected XSS.
//   5. Stop testing further payloads for this parameter (break).
//
// Why nonces? A random nonce ensures that each test is unique and cannot be
// confused with existing page content — avoids false positives.
//
// OWASP: A05:2025 Injection | CWE-79
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/url"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type xssPayload struct {
	template string // contains %NONCE% placeholder
	context  string // injection context label
	severity string
}

// xssPayloads covers four injection contexts.
// Detection checks whether the nonce appears in the response body,
// which catches both verbatim and partially-encoded reflections.
var xssPayloads = []xssPayload{
	{`<script>/*%NONCE%*/</script>`, "html_body", "High"},
	{`"><img src=x onerror=/*%NONCE%*/>`, "html_attr", "High"},
	{`';/*%NONCE%*/`, "js_context", "Medium"},
	{`va-%NONCE%-probe`, "reflection", "Medium"},
}

type XSSScanner struct{}

func (x *XSSScanner) Name() string {
	return "xss"
}

func (x *XSSScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	parsed, err := url.Parse(u.URL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	if len(q) == 0 {
		return nil
	}

	nonce := generateNonce()
	client := httpclient.NewClient()
	findings := []model.Finding{}
	idx := 0

	for key := range q {
		if ctx.Err() != nil {
			return findings
		}

		// Try each payload until a reflection is confirmed for this parameter.
		for _, pl := range xssPayloads {
			if ctx.Err() != nil {
				return findings
			}

			probe := probeValue(pl.template, nonce)
			testURL := *parsed
			testQ := testURL.Query()
			testQ.Set(key, probe)
			testURL.RawQuery = testQ.Encode()

			req, err := httpclient.NewRequestCtx(ctx, testURL.String())
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()

			// Search for nonce in body -- catches encoded and verbatim reflections.
			if strings.Contains(string(body), nonce) {
				f := model.NewFinding(
					"xss",
					"reflected_input",
					"Potential Reflected XSS",
					"Injected probe was reflected in the response without sufficient sanitization. Context: "+pl.context+".",
					pl.severity,
					standards.A05Injection,
					testURL.String(),
					"Parameter '"+key+"' reflected probe (context: "+pl.context+")",
					"Apply context-aware output encoding (HTML, attribute, JavaScript) and strict server-side input validation.",
					standards.A05URL+" | "+standards.XSSCommunityURL,
				)
				f.ID = buildID("XSS", u.URL, idx)
				f.CWEIDs = []string{"CWE-79"}
				findings = append(findings, f)
				idx++
				break // confirmed for this parameter; skip remaining payloads
			}
		}
	}

	return findings
}

// generateNonce returns a random 8-character hex string per scan invocation.
func generateNonce() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "va1xprobe"
	}
	return hex.EncodeToString(b)
}

// probeValue replaces the %NONCE% placeholder in a payload template.
func probeValue(template, nonce string) string {
	return strings.ReplaceAll(template, "%NONCE%", nonce)
}
