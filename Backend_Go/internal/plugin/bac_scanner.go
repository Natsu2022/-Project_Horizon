package plugin

// ─── BACScanner — Broken Access Control (A01:2025) ───────────────────────────
//
// Receives: URLInfo (one URL per call)
// Does:     1 GET request on the URL + extra requests for path probing / redirect test
// Returns:  []Finding  (variable count depending on what is found)
//
// Checks performed (in order):
//
//   1. Directory Listing (CWE-548)
//      Regex matches "Index of /" or "Directory listing for" in the body.
//
//   2. CSRF — Missing Token in POST Form (CWE-352)
//      Finds all <form method="post"> tags; flags any that lack a csrf/token
//      hidden input field. Reports at most one finding per page.
//
//   3. Sensitive Information in HTML Comments (CWE-615)
//      Extracts all <!-- ... --> comments; flags any containing keywords:
//      password, secret, api_key, token, credential, auth, debug, etc.
//
//   4. Cookie Missing SameSite Attribute (CWE-1275)
//      Inspects every Set-Cookie header in the response; flags cookies
//      that do not include a SameSite directive.
//
//   5. Open Redirect (CWE-601)
//      Detects redirect-like query params (url, redirect, next, return, goto…).
//      Injects "https://evil-redirect-probe.example.com" as the value.
//      Uses a no-redirect client; checks if Location header contains the probe.
//
//   6. Sensitive Path Probing (CWE-425/538/540/200/497) — depth==0 ONLY
//      Probes 15 well-known sensitive paths (/.env, /.git/config, /admin,
//      /phpinfo.php, /actuator/env, etc.) against the site's base URL.
//      A finding is raised only when the server returns HTTP 200.
//
// OWASP: A01:2025 Broken Access Control
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

// BACScanner checks for Broken Access Control vulnerabilities (OWASP A01:2025).
type BACScanner struct{}

func (b *BACScanner) Name() string { return "bac" }

var (
	dirListRegex    = regexp.MustCompile(`(?i)(Index of /|Directory listing for|Parent Directory<)`)
	postFormRegex   = regexp.MustCompile(`(?is)<form[^>]+method=["']?post["']?[^>]*>.*?</form>`)
	csrfInputRegex  = regexp.MustCompile(`(?i)name=["']?[\w-]*(csrf|_token|nonce|authenticity)[\w-]*["']?`)
	htmlCommentRegex = regexp.MustCompile(`(?s)<!--(.*?)-->`)
)

var sensitiveCommentKeywords = []string{
	"password", "passwd", "secret", "api_key", "apikey",
	"token", "private", "credential", "auth", "debug",
}

var redirectParamNames = []string{
	"url", "redirect", "next", "return", "goto", "redir",
	"returnurl", "return_url", "callback", "forward", "dest",
	"destination", "redirect_uri", "redirect_url",
}

type sensitivePath struct {
	path     string
	title    string
	desc     string
	severity string
	cwe      string
}

var sensitivePaths = []sensitivePath{
	{"/.env", "Exposed .env File",
		"Environment configuration file is publicly accessible, potentially exposing credentials and API keys.",
		"Critical", "CWE-538"},
	{"/.git/config", "Exposed Git Repository Config",
		"Git configuration file is publicly accessible, leaking repository structure and remote URLs.",
		"High", "CWE-540"},
	{"/backup", "Accessible Backup Directory",
		"A backup directory is accessible without authentication.",
		"High", "CWE-425"},
	{"/backup.zip", "Accessible Backup Archive",
		"A backup archive file is downloadable without authentication.",
		"High", "CWE-425"},
	{"/backup.tar.gz", "Accessible Backup Archive",
		"A backup archive file is downloadable without authentication.",
		"High", "CWE-425"},
	{"/admin", "Admin Panel Accessible",
		"An administrative interface returned HTTP 200 without apparent authentication enforcement.",
		"High", "CWE-425"},
	{"/phpinfo.php", "PHP Info Page Exposed",
		"phpinfo() output reveals sensitive server configuration, PHP version, and environment variables.",
		"Medium", "CWE-200"},
	{"/web.config", "Exposed web.config",
		"ASP.NET web.config file is publicly accessible, potentially exposing connection strings and secrets.",
		"High", "CWE-540"},
	{"/config.php", "Exposed config.php",
		"PHP configuration file is publicly accessible.",
		"High", "CWE-540"},
	{"/wp-admin/", "WordPress Admin Panel Exposed",
		"WordPress admin login panel is directly accessible.",
		"Medium", "CWE-425"},
	{"/server-status", "Apache Server Status Page",
		"Apache server-status page leaks real-time server metrics and request details.",
		"Medium", "CWE-200"},
	{"/actuator/env", "Spring Boot Actuator /env Exposed",
		"Spring Boot actuator env endpoint may expose environment variables and configuration secrets.",
		"High", "CWE-497"},
	{"/actuator/health", "Spring Boot Actuator /health Exposed",
		"Spring Boot actuator health endpoint exposes internal application state.",
		"Low", "CWE-497"},
	{"/.DS_Store", "Exposed .DS_Store File",
		"macOS directory metadata file leaks directory structure and filenames.",
		"Low", "CWE-538"},
	{"/crossdomain.xml", "Permissive crossdomain.xml",
		"A cross-domain policy file was found; overly permissive policies allow unauthorized cross-origin access.",
		"Medium", "CWE-284"},
}

func (b *BACScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, u.URL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("[BACScanner] error:", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	var findings []model.Finding

	// CWE-548: Directory listing
	if dirListRegex.MatchString(bodyStr) {
		f := model.NewFinding("bac", "directory_listing",
			"Directory Listing Enabled",
			"The server exposes a directory listing, revealing file structure and potentially sensitive files.",
			"Medium", standards.A01BrokenAccessControl, u.URL,
			"Directory listing detected in response body",
			"Disable directory listing on the web server (e.g., Options -Indexes in Apache, autoindex off in Nginx).",
			standards.A01URL)
		f.CWEIDs = []string{"CWE-548"}
		findings = append(findings, f)
	}

	// CWE-352: CSRF — POST forms without CSRF token field
	forms := postFormRegex.FindAllString(bodyStr, -1)
	for _, form := range forms {
		if !csrfInputRegex.MatchString(form) {
			f := model.NewFinding("bac", "csrf_missing_token",
				"Missing CSRF Token in POST Form",
				"A POST form was found without a CSRF token input field, making it potentially vulnerable to Cross-Site Request Forgery.",
				"High", standards.A01BrokenAccessControl, u.URL,
				"POST form without csrf/token hidden field detected",
				"Add a server-generated CSRF token to every state-changing form and validate it on submission.",
				standards.A01URL)
			f.CWEIDs = []string{"CWE-352"}
			findings = append(findings, f)
			break // one finding per page
		}
	}

	// CWE-615: Sensitive information in HTML comments
	comments := htmlCommentRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range comments {
		if len(m) < 2 {
			continue
		}
		lower := strings.ToLower(m[1])
		for _, kw := range sensitiveCommentKeywords {
			if strings.Contains(lower, kw) {
				evidence := strings.TrimSpace(m[0])
				if len(evidence) > 200 {
					evidence = evidence[:200] + "..."
				}
				f := model.NewFinding("bac", "sensitive_comment",
					"Sensitive Information in HTML Comment",
					"An HTML comment contains potentially sensitive information (e.g., credentials, keys, or debug data).",
					"Low", standards.A01BrokenAccessControl, u.URL,
					evidence,
					"Remove all sensitive information from HTML comments before deploying to production.",
					standards.A01URL)
				f.CWEIDs = []string{"CWE-615", "CWE-540"}
				findings = append(findings, f)
				break
			}
		}
	}

	// CWE-1275: Cookie missing SameSite attribute
	for _, setCookie := range resp.Header["Set-Cookie"] {
		lc := strings.ToLower(setCookie)
		if !strings.Contains(lc, "samesite") {
			cookieName := strings.SplitN(setCookie, "=", 2)[0]
			f := model.NewFinding("bac", "cookie_no_samesite",
				"Cookie Missing SameSite Attribute",
				"A cookie is set without the SameSite attribute, increasing the risk of CSRF attacks.",
				"Low", standards.A01BrokenAccessControl, u.URL,
				"Set-Cookie: "+cookieName+" (SameSite attribute absent)",
				"Add SameSite=Strict or SameSite=Lax to all cookies, especially session and authentication cookies.",
				standards.A01URL)
			f.CWEIDs = []string{"CWE-1275", "CWE-352"}
			findings = append(findings, f)
		}
	}

	// CWE-601: Open Redirect — test redirect-like query parameters
	parsed, err := url.Parse(u.URL)
	if err == nil {
		q := parsed.Query()
		for _, paramName := range redirectParamNames {
			if _, exists := q[paramName]; exists {
				if rf := b.checkOpenRedirect(ctx, u.URL, paramName); rf != nil {
					findings = append(findings, *rf)
				}
				break
			}
		}
	}

	// CWE-425/538/540/200/497: Sensitive path probing — only from the root URL
	if u.Depth == 0 {
		baseURL := extractBaseURL(u.URL)
		for _, sp := range sensitivePaths {
			if ctx.Err() != nil {
				break
			}
			if pf := b.probePath(ctx, baseURL, sp); pf != nil {
				findings = append(findings, *pf)
			}
		}
	}

	for i := range findings {
		findings[i].ID = buildID("BAC", u.URL, i)
	}
	return findings
}

// checkOpenRedirect sends a request with an external URL injected into the redirect parameter
// and checks whether the server responds with a redirect to that external URL.
func (b *BACScanner) checkOpenRedirect(ctx context.Context, rawURL, param string) *model.Finding {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	q.Set(param, "https://evil-redirect-probe.example.com")
	parsed.RawQuery = q.Encode()
	testURL := parsed.String()

	client := httpclient.NewClientNoRedirect()
	req, err := httpclient.NewRequestCtx(ctx, testURL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "evil-redirect-probe.example.com") {
		f := model.NewFinding("bac", "open_redirect",
			"Open Redirect via '"+param+"' Parameter",
			"The application redirects users to an attacker-controlled URL via the '"+param+"' query parameter without validation.",
			"Medium", standards.A01BrokenAccessControl, rawURL,
			"Redirect Location: "+loc,
			"Validate redirect destinations server-side. Use a whitelist of allowed URLs or restrict to relative paths only.",
			standards.A01URL)
		f.CWEIDs = []string{"CWE-601"}
		return &f
	}
	return nil
}

// probePath checks whether a sensitive path returns HTTP 200 from the target's base URL.
func (b *BACScanner) probePath(ctx context.Context, baseURL string, sp sensitivePath) *model.Finding {
	targetURL := baseURL + sp.path
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, targetURL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	f := model.NewFinding("bac", "forced_browsing",
		sp.title, sp.desc, sp.severity,
		standards.A01BrokenAccessControl, targetURL,
		"HTTP 200 OK returned for sensitive path: "+sp.path,
		"Restrict access to sensitive paths using authentication, authorization, and deny-all server rules.",
		standards.A01URL)
	cweIDs := []string{sp.cwe}
	if sp.cwe != "CWE-425" {
		cweIDs = append(cweIDs, "CWE-425")
	}
	f.CWEIDs = append(cweIDs, "CWE-862")
	return &f
}

func extractBaseURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}
