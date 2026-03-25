package model

// ─── Core Data Structures ────────────────────────────────────────────────────
//
// This package defines all data structures shared across the VA Scanner layers.
//
// End-to-end data flow:
//
//   [GUI] builds ScanRequest → POST /scan (JSON)
//         ↓
//   [api.ScanHandler] validates/clamps fields
//         ↓
//   [engine.ScannerEngine] receives ScanRequest
//         ├─ Crawler → []URLInfo          (all pages found on the target site)
//         └─ for each URLInfo:
//               each Plugin.Scan() → []Finding   (one check per URL)
//         ↓
//   Engine aggregates → deduplicates → sorts → generates reports
//         ↓
//   ScanResponse (JSON) → GUI displays findings, stats, and report buttons
//
// ─────────────────────────────────────────────────────────────────────────────

import "time"

// URLInfo represents a single URL discovered by the crawler.
// Depth=0 is the seed/root URL; deeper pages have higher depth values.
// Plugins use Depth to restrict certain checks to the root only (e.g., bac path probing).
type URLInfo struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}

// ModuleOptions controls which scanner plugins are enabled for a scan.
// Each field corresponds to one plugin (true = enabled, false = skip).
// The GUI exposes these as checkboxes; the JSON field names match exactly.
type ModuleOptions struct {
	Headers   bool `json:"headers"`
	Misconfig bool `json:"misconfig"`
	TLS       bool `json:"tls"`
	XSS       bool `json:"xss"`
	SQLi      bool `json:"sqli"`
	CVE       bool `json:"cve"`
	ZAP       bool `json:"zap"`
	BAC       bool `json:"bac"`
}

// AuthConfig holds credentials for form-based authentication.
// When Enabled is true, the engine performs a login POST before crawling
// and propagates the resulting session cookies to all scanner requests.
// UsernameField / PasswordField are the HTML form field names (not the values).
type AuthConfig struct {
	Enabled       bool   `json:"enabled"`
	LoginURL      string `json:"login_url"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

// ScanRequest is the JSON body sent by the GUI to POST /scan.
// api.ScanHandler validates and clamps the fields before passing it to the engine.
type ScanRequest struct {
	Target         string        `json:"target"`
	MaxPages       int           `json:"max_pages"`
	MaxDepth       int           `json:"max_depth"`
	RequestDelayMs int           `json:"request_delay_ms"`
	Options        ModuleOptions `json:"options"`
	ReportFormats  []string      `json:"report_formats"`
	ZAPBaseURL     string        `json:"zap_base_url"`
	ZAPAPIKey      string        `json:"zap_api_key"`
	TimedMode      bool          `json:"timed_mode"`
	TimeLimitSecs  int           `json:"time_limit_secs"`
	FullScanMode   bool          `json:"full_scan_mode"`
	Auth           AuthConfig    `json:"auth"`
}

// Finding represents a single security vulnerability discovered by a plugin.
// Every plugin produces zero or more Findings per scanned URL.
// The engine deduplicates by (Type|TargetURL|Evidence) before returning results.
type Finding struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Module         string   `json:"module"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvss_score"`
	OWASPCategory  string   `json:"owasp_category"`
	CWEIDs         []string `json:"cwe_ids,omitempty"`
	TargetURL      string   `json:"target_url"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	References     string   `json:"references"`
	DetectedAt     string   `json:"detected_at"`
	Request        string   `json:"request,omitempty"`
	Response       string   `json:"response,omitempty"`
}

// ReportArtifact records the format and file path of a generated report.
// Returned inside ScanResponse so the GUI can show "Open Report" buttons.
type ReportArtifact struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}

// ScanStats holds aggregate counters calculated by the engine after scanning.
// Displayed in the GUI dashboard (total, critical, high, medium, low).
type ScanStats struct {
	ScannedURLs      int `json:"scanned_urls"`
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`
}

// ScanResponse is the complete JSON payload returned by POST /scan.
// The GUI receives this and renders findings, stats, and report buttons.
type ScanResponse struct {
	OWASP      string           `json:"owasp"`
	ScanID     string           `json:"scan_id"`
	Target     string           `json:"target"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Stats      ScanStats        `json:"stats"`
	Findings   []Finding        `json:"findings"`
	Reports    []ReportArtifact `json:"reports"`
}

func NewDefaultRequest(target string) ScanRequest {
	return ScanRequest{
		Target:   target,
		MaxPages: 30,
		MaxDepth: 2,
		Options: ModuleOptions{
			Headers:   true,
			Misconfig: true,
			TLS:       true,
			XSS:       true,
			SQLi:      true,
			CVE:       true,
		},
		ReportFormats: []string{"json", "html", "pdf"},
	}
}

// NewFinding is a factory function used by every plugin to create a Finding.
// CVSSScore is derived automatically from severity via ScoreBySeverity.
// DetectedAt is set to the current time in RFC3339 format.
func NewFinding(module, findingType, title, description, severity, owasp, targetURL, evidence, recommendation, refs string) Finding {
	return Finding{
		Type:           findingType,
		Module:         module,
		Title:          title,
		Description:    description,
		Severity:       severity,
		CVSSScore:      ScoreBySeverity(severity),
		OWASPCategory:  owasp,
		TargetURL:      targetURL,
		Evidence:       evidence,
		Recommendation: recommendation,
		References:     refs,
		DetectedAt:     time.Now().Format(time.RFC3339),
	}
}

func ScoreBySeverity(sev string) float64 {
	switch sev {
	case "Critical":
		return 9.4
	case "High":
		return 8.2
	case "Medium":
		return 6.1
	case "Low":
		return 3.7
	default:
		return 0.0
	}
}
