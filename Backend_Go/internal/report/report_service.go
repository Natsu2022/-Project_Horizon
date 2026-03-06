package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type reportPayload struct {
	OWASP      string          `json:"owasp"`
	ScanID     string          `json:"scan_id"`
	Target     string          `json:"target"`
	FinishedAt string          `json:"finished_at"`
	Stats      model.ScanStats `json:"stats"`
	Findings   []model.Finding `json:"findings"`
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
