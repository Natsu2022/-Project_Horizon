package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type reportPayload struct {
	OWASP       string          `json:"owasp"`
	ScanID      string          `json:"scan_id"`
	Target      string          `json:"target"`
	FinishedAt  string          `json:"finished_at"`
	Stats       model.ScanStats `json:"stats"`
	Findings    []model.Finding `json:"findings"`
	ExecSummary string          `json:"-"` // auto-generated narrative overview
	Methodology string          `json:"-"` // static methodology description
	Conclusions string          `json:"-"` // auto-generated from severity results
}

func GenerateArtifacts(scanID, target string, findings []model.Finding, stats model.ScanStats, formats []string) []model.ReportArtifact {
	if len(formats) == 0 {
		formats = []string{"json", "html", "pdf"}
	}

	dir := filepath.Join("reports", scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil
	}

	payload := reportPayload{
		OWASP:      standards.OWASPTop10Version,
		ScanID:     scanID,
		Target:     target,
		FinishedAt: time.Now().Format(time.RFC3339),
		Stats:      stats,
		Findings:   findings,
	}
	payload.ExecSummary = buildExecSummary(payload)
	payload.Methodology = buildMethodologyText()
	payload.Conclusions = buildConclusions(payload)

	artifacts := make([]model.ReportArtifact, 0, len(formats))
	for _, format := range formats {
		switch strings.ToLower(strings.TrimSpace(format)) {
		case "json":
			path := filepath.Join(dir, "report.json")
			if writeJSON(path, payload) == nil {
				artifacts = append(artifacts, model.ReportArtifact{Format: "json", Path: absPath(path)})
			}
		case "html":
			path := filepath.Join(dir, "report.html")
			if writeHTML(path, payload) == nil {
				artifacts = append(artifacts, model.ReportArtifact{Format: "html", Path: absPath(path)})
			}
		case "pdf":
			path := filepath.Join(dir, "report.pdf")
			if writePDF(path, payload) == nil {
				artifacts = append(artifacts, model.ReportArtifact{Format: "pdf", Path: absPath(path)})
			}
		}
	}

	return artifacts
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func writeJSON(path string, payload reportPayload) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// buildExecSummary generates a short narrative paragraph from scan statistics.
func buildExecSummary(p reportPayload) string {
	if p.Stats.TotalFindings == 0 {
		return fmt.Sprintf(
			"This assessment scanned %d URL(s) on %s. No security findings were identified during this scan. "+
				"The target appears to be well-configured against the tested vulnerability classes.",
			p.Stats.ScannedURLs, p.Target,
		)
	}
	top := "N/A"
	if len(p.Findings) > 0 {
		top = p.Findings[0].Title
	}
	return fmt.Sprintf(
		"This assessment scanned %d URL(s) on %s and identified %d finding(s): "+
			"%d critical, %d high, %d medium, and %d low severity. "+
			"The highest-severity finding is: %s. "+
			"Detailed findings, evidence, and remediation guidance are provided in the sections below.",
		p.Stats.ScannedURLs, p.Target,
		p.Stats.TotalFindings,
		p.Stats.CriticalFindings, p.Stats.HighFindings,
		p.Stats.MediumFindings, p.Stats.LowFindings,
		top,
	)
}

// buildMethodologyText returns a static description of the scanning methodology.
func buildMethodologyText() string {
	return "The assessment followed a four-phase methodology: " +
		"(1) Discovery — a breadth-first crawler identified reachable endpoints within the configured depth and page limits, restricted to the target host. " +
		"(2) Plugin Scan — each discovered URL was tested by the enabled scanner modules: HTTP security headers inspection, TLS/configuration checks, " +
		"injection testing (XSS, SQL Injection, OS Command Injection), broken access control analysis, CVE banner matching, and optional OWASP ZAP integration. " +
		"(3) OWASP Mapping — every finding was classified against OWASP Top 10:2025 categories (A01-A10) and assigned a CVSS score derived from severity. " +
		"(4) Reporting — deduplicated and severity-sorted findings were compiled into this report in JSON, HTML, and PDF formats."
}

// buildConclusions auto-generates a risk conclusion from severity counts.
// Top-3 unique recommendations from the highest-severity findings are included.
func buildConclusions(p reportPayload) string {
	// Collect up to 3 distinct recommendations from the top findings.
	seen := map[string]bool{}
	recs := []string{}
	for _, f := range p.Findings {
		if f.Recommendation == "" {
			continue
		}
		if !seen[f.Recommendation] {
			seen[f.Recommendation] = true
			recs = append(recs, fmt.Sprintf("- %s", f.Recommendation))
		}
		if len(recs) >= 3 {
			break
		}
	}
	recBlock := ""
	if len(recs) > 0 {
		recBlock = " Key recommendations:\n" + strings.Join(recs, "\n")
	}

	if p.Stats.CriticalFindings > 0 || p.Stats.HighFindings > 0 {
		return "IMMEDIATE ACTION REQUIRED. The scan identified critical or high-severity vulnerabilities that represent significant risk to the target system. " +
			"Remediation should begin immediately, prioritising the highest-severity findings." + recBlock
	}
	if p.Stats.MediumFindings > 0 {
		return "REMEDIATION RECOMMENDED. Medium-severity findings were identified that should be addressed in the next development or maintenance cycle." + recBlock
	}
	return "No significant vulnerabilities were identified. The target appears to be well-configured against the tested vulnerability classes. " +
		"Continue to apply security best practices and schedule regular re-assessments."
}
