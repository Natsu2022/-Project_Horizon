package plugin

import (
	"context"
	"io"
	"regexp"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

// cveSignature defines a detectable outdated/vulnerable software pattern.
// header: HTTP header to inspect; empty string means check response body.
// contains: lowercase substring to match; empty string means presence-only check.
type cveSignature struct {
	header    string
	contains  string
	title     string
	evidence  string
	severity  string
	reference string
}

var cveSignatures = []cveSignature{
	// --- Server header ---
	{"Server", "apache/2.2", "Apache 2.2 (EOL)", "Server header: Apache/2.2.x", "High", "https://httpd.apache.org/security/vulnerabilities_22.html"},
	{"Server", "apache/2.4.4", "Apache 2.4.4 (Vulnerable)", "Server header: Apache/2.4.4", "High", "https://httpd.apache.org/security/vulnerabilities_24.html"},
	{"Server", "apache/2.4.6", "Apache 2.4.6 (Vulnerable)", "Server header: Apache/2.4.6", "Medium", "https://httpd.apache.org/security/vulnerabilities_24.html"},
	{"Server", "nginx/1.14", "Nginx 1.14 (EOL)", "Server header: nginx/1.14.x", "Medium", "https://nginx.org/en/security_advisories.html"},
	{"Server", "nginx/1.16", "Nginx 1.16 (EOL)", "Server header: nginx/1.16.x", "Medium", "https://nginx.org/en/security_advisories.html"},
	{"Server", "nginx/1.18", "Nginx 1.18 (EOL)", "Server header: nginx/1.18.x", "Low", "https://nginx.org/en/security_advisories.html"},
	{"Server", "iis/6.0", "IIS 6.0 (EOL)", "Server header: Microsoft-IIS/6.0", "High", "https://msrc.microsoft.com/update-guide/"},
	{"Server", "iis/7.5", "IIS 7.5 (Legacy)", "Server header: Microsoft-IIS/7.5", "High", "https://msrc.microsoft.com/update-guide/"},
	{"Server", "openssl/1.0", "OpenSSL 1.0.x (EOL)", "Server header includes OpenSSL/1.0", "High", "https://www.openssl.org/news/vulnerabilities.html"},
	{"Server", "lighttpd/1.4", "Lighttpd 1.4.x (old)", "Server header: lighttpd/1.4.x", "Low", "https://www.lighttpd.net/security/"},

	// --- X-Powered-By header ---
	{"X-Powered-By", "php/5.", "PHP 5.x (EOL)", "X-Powered-By: PHP/5.x", "High", "https://www.php.net/eol.php"},
	{"X-Powered-By", "php/7.0", "PHP 7.0 (EOL)", "X-Powered-By: PHP/7.0", "High", "https://www.php.net/eol.php"},
	{"X-Powered-By", "php/7.1", "PHP 7.1 (EOL)", "X-Powered-By: PHP/7.1", "High", "https://www.php.net/eol.php"},
	{"X-Powered-By", "php/7.2", "PHP 7.2 (EOL)", "X-Powered-By: PHP/7.2", "Medium", "https://www.php.net/eol.php"},
	{"X-Powered-By", "php/7.3", "PHP 7.3 (EOL)", "X-Powered-By: PHP/7.3", "Medium", "https://www.php.net/eol.php"},
	{"X-Powered-By", "asp.net", "ASP.NET version disclosed", "X-Powered-By: ASP.NET", "Low", "https://owasp.org/www-project-web-security-testing-guide/"},

	// --- X-AspNet-Version header (presence = version disclosure) ---
	{"X-AspNet-Version", "", "ASP.NET version disclosed via header", "X-AspNet-Version header present", "Low", "https://owasp.org/www-project-web-security-testing-guide/"},

	// --- X-Generator header ---
	{"X-Generator", "drupal 7", "Drupal 7 (EOL)", "X-Generator: Drupal 7", "High", "https://www.drupal.org/psa-2023-06-07"},
	{"X-Generator", "drupal 8", "Drupal 8 (EOL)", "X-Generator: Drupal 8", "High", "https://www.drupal.org/psa-2023-06-07"},
	{"X-Generator", "joomla! 3", "Joomla 3.x (EOL)", "X-Generator: Joomla! 3", "High", "https://developer.joomla.org/security-centre.html"},

	// --- X-Drupal-Cache (presence reveals Drupal) ---
	{"X-Drupal-Cache", "", "Drupal installation detected", "X-Drupal-Cache header present", "Low", "https://www.drupal.org/security"},

	// --- Response body meta generator ---
	{"", "wordpress 4.", "WordPress 4.x (EOL)", "meta generator: WordPress 4.x", "High", "https://wordpress.org/news/category/security/"},
	{"", "wordpress 5.0", "WordPress 5.0 (Vulnerable)", "meta generator: WordPress 5.0", "High", "https://wordpress.org/news/category/security/"},
	{"", "wordpress 5.1", "WordPress 5.1 (Vulnerable)", "meta generator: WordPress 5.1", "High", "https://wordpress.org/news/category/security/"},
	{"", "wordpress", "WordPress installation detected", "meta generator contains WordPress", "Low", "https://wordpress.org/news/category/security/"},
	{"", "joomla! 3.", "Joomla 3.x (EOL)", "meta generator: Joomla! 3", "High", "https://developer.joomla.org/security-centre.html"},
	{"", "jquery v1.", "jQuery 1.x (EOL)", "meta/script references jQuery 1.x", "Medium", "https://blog.jquery.com/category/security/"},
}

var metaGeneratorRegex = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

type CVEScanner struct{}

func (c *CVEScanner) Name() string {
	return "cve"
}

func (c *CVEScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, u.URL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()

	bodyLower := strings.ToLower(string(body))
	metaContent := extractMetaGenerator(bodyLower)

	headerValues := map[string]string{
		"Server":            strings.ToLower(resp.Header.Get("Server")),
		"X-Powered-By":      strings.ToLower(resp.Header.Get("X-Powered-By")),
		"X-AspNet-Version":  strings.ToLower(resp.Header.Get("X-AspNet-Version")),
		"X-Generator":       strings.ToLower(resp.Header.Get("X-Generator")),
		"X-Drupal-Cache":    strings.ToLower(resp.Header.Get("X-Drupal-Cache")),
		"X-WordPress-Cache": strings.ToLower(resp.Header.Get("X-WordPress-Cache")),
	}

	findings := []model.Finding{}
	for idx, sig := range cveSignatures {
		var target string
		if sig.header == "" {
			target = metaContent
		} else {
			target = headerValues[sig.header]
		}

		// presence-only check (contains is empty) or substring match
		var matched bool
		if sig.contains == "" {
			matched = target != ""
		} else {
			matched = strings.Contains(target, sig.contains)
		}

		if matched {
			f := model.NewFinding(
				"cve",
				"legacy_software_version",
				sig.title,
				"Detected outdated or vulnerable software version. Upgrade to a supported release and review security advisories.",
				sig.severity,
				standards.A03SupplyChainFailures,
				u.URL,
				sig.evidence,
				"Upgrade server software and validate against the latest security advisories.",
				standards.A03URL+" | "+sig.reference,
			)
			f.ID = buildID("CVE", u.URL, idx)
			findings = append(findings, f)
		}
	}

	return findings
}

func extractMetaGenerator(bodyLower string) string {
	m := metaGeneratorRegex.FindStringSubmatch(bodyLower)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
