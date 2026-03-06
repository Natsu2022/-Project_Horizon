package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"vuln_assessment_app/internal/engine"
	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
)

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	req.Target = httpclient.EnsureURLScheme(req.Target)

	if req.MaxPages <= 0 {
		req.MaxPages = 30
	}
	if req.MaxPages > 200 {
		req.MaxPages = 200
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 2
	}
	if req.MaxDepth > 4 {
		req.MaxDepth = 4
	}
	if req.RequestDelayMs < 0 {
		req.RequestDelayMs = 0
	}
	if req.RequestDelayMs > 500 {
		req.RequestDelayMs = 500
	}
	if req.Options.ZAP && req.ZAPBaseURL == "" {
		req.ZAPBaseURL = "http://localhost:8880"
	}
	if len(req.ReportFormats) == 0 {
		req.ReportFormats = []string{"json", "html", "pdf"}
	}

	if req.Options == (model.ModuleOptions{}) {
		req.Options = model.ModuleOptions{Headers: true, Misconfig: true, TLS: true, XSS: true, SQLi: true, CVE: true}
	}

	scanner := engine.NewEngine(req)
	result := scanner.Run(r.Context())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
