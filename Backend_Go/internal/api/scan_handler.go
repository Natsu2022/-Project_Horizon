package api

// ─── POST /scan — HTTP Request Handler ───────────────────────────────────────
//
// Receives: POST /scan with JSON body (model.ScanRequest)
// Returns:  JSON (model.ScanResponse)
//
// Responsibilities:
//   1. Parse and validate JSON body — reject bad input with 400.
//   2. Normalise target URL (add scheme if missing).
//   3. Clamp parameters to safe ranges:
//        MaxPages       → 1–200    (default 30)
//        MaxDepth       → 1–4      (default 2)
//        RequestDelayMs → 0–500 ms (default 0)
//   4. Handle TimedMode — disables page/depth limits and applies a
//        context timeout of TimeLimitSecs (max 3600 s, default 300 s).
//   5. Build ScannerEngine and call Run(ctx).
//   6. Return ScanResponse as JSON 200.
//
// Called by: main.go route registration  → POST /scan
// Delegates to: engine.NewEngine(req).Run(scanCtx)
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vuln_assessment_app/internal/engine"
	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
)

func ScanHandler(c *gin.Context) {
	var req model.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
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
		req.Options = model.ModuleOptions{Headers: true, Misconfig: true, TLS: true, XSS: true, SQLi: true, CVE: true, BAC: true}
	}

	var scanCtx context.Context
	if req.TimedMode {
		req.MaxPages = 999999
		req.MaxDepth = 99
		if req.TimeLimitSecs <= 0 {
			req.TimeLimitSecs = 300
		}
		if req.TimeLimitSecs > 3600 {
			req.TimeLimitSecs = 3600
		}
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(c.Request.Context(), time.Duration(req.TimeLimitSecs)*time.Second)
		defer cancel()
	} else {
		scanCtx = c.Request.Context()
	}

	scanner := engine.NewEngine(req)
	result := scanner.Run(scanCtx)

	c.JSON(http.StatusOK, result)
}
