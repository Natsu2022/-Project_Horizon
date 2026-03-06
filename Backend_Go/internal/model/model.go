package model

import "time"

type URLInfo struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}

type ModuleOptions struct {
	Headers   bool `json:"headers"`
	Misconfig bool `json:"misconfig"`
	TLS       bool `json:"tls"`
	XSS       bool `json:"xss"`
	SQLi      bool `json:"sqli"`
	CVE       bool `json:"cve"`
	ZAP       bool `json:"zap"`
}

type ScanRequest struct {
	Target         string        `json:"target"`
	MaxPages       int           `json:"max_pages"`
	MaxDepth       int           `json:"max_depth"`
	RequestDelayMs int           `json:"request_delay_ms"`
	Options        ModuleOptions `json:"options"`
	ReportFormats  []string      `json:"report_formats"`
	ZAPBaseURL     string        `json:"zap_base_url"`
	ZAPAPIKey      string        `json:"zap_api_key"`
}

type Finding struct {
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	Module         string  `json:"module"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Severity       string  `json:"severity"`
	CVSSScore      float64 `json:"cvss_score"`
	OWASPCategory  string  `json:"owasp_category"`
	TargetURL      string  `json:"target_url"`
	Evidence       string  `json:"evidence"`
	Recommendation string  `json:"recommendation"`
	References     string  `json:"references"`
	DetectedAt     string  `json:"detected_at"`
}

type ReportArtifact struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}

type ScanStats struct {
	ScannedURLs      int `json:"scanned_urls"`
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`
}

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
