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
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vuln_assessment_app/internal/engine"
	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
)

var (
	// authEmailRe / authUsernameRe mirror the GUI-side validation in main.py.
	// Email: standard user@domain.tld pattern.
	// Username: 3–64 chars, letters/digits/underscores/hyphens/dots.
	authEmailRe    = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	authUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-.]{3,64}$`)
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
	// ZAPBaseURL is intentionally left empty when not provided:
	// ZAPScanner.resolveBaseURL() will probe common ports (8080, 8880, 8090, 8443)
	// and use the first one that responds.
	if len(req.ReportFormats) == 0 {
		req.ReportFormats = []string{"json", "html", "pdf"}
	}

	if req.Auth.Enabled {
		req.Auth.LoginURL = strings.TrimSpace(req.Auth.LoginURL)
		if req.Auth.LoginURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "auth.login_url is required when authentication is enabled"})
			return
		}
		req.Auth.Username = strings.TrimSpace(req.Auth.Username)
		if req.Auth.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "auth.username is required when authentication is enabled"})
			return
		}
		if !authEmailRe.MatchString(req.Auth.Username) && !authUsernameRe.MatchString(req.Auth.Username) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "auth.username must be a valid email address or username (3–64 chars)"})
			return
		}
		if len(req.Auth.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "auth.password must be at least 8 characters"})
			return
		}
		if req.Auth.UsernameField == "" {
			req.Auth.UsernameField = "username"
		}
		if req.Auth.PasswordField == "" {
			req.Auth.PasswordField = "password"
		}
	}

	if req.BruteForce.Enabled {
		if req.BruteForce.LoginURL == "" {
			req.BruteForce.LoginURL = strings.TrimSpace(req.Auth.LoginURL)
		} else {
			req.BruteForce.LoginURL = strings.TrimSpace(req.BruteForce.LoginURL)
		}
		if req.BruteForce.LoginURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "brute_force.login_url is required"})
			return
		}
		if len(req.BruteForce.Usernames) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "brute_force.usernames must not be empty"})
			return
		}
		if len(req.BruteForce.Passwords) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "brute_force.passwords must not be empty"})
			return
		}
		if req.BruteForce.DelayMs < 100 {
			req.BruteForce.DelayMs = 100
		}
		if req.BruteForce.MaxAttempts <= 0 {
			req.BruteForce.MaxAttempts = 100
		}
		if req.BruteForce.MaxAttempts > 500 {
			req.BruteForce.MaxAttempts = 500
		}
	}

	var scanCtx context.Context
	if req.FullScanMode {
		// Full Scan: no page/depth ceiling, no time limit.
		// The crawler terminates naturally when BFS exhausts all reachable URLs on the host.
		req.MaxPages = 999_999
		req.MaxDepth = 99
		scanCtx = c.Request.Context()
	} else if req.TimedMode {
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

	// Wrap with an extra cancel layer so POST /cancel can stop the scan
	// immediately — Python's session.close() alone does not reliably abort
	// the in-flight HTTP request on the client side.
	scanCtx, apiCancel := context.WithCancel(scanCtx)
	defer apiCancel()
	engine.SetGlobalCancel(apiCancel)
	defer engine.SetGlobalCancel(nil)

	scanner := engine.NewEngine(req)
	result := scanner.Run(scanCtx)

	c.JSON(http.StatusOK, result)
}
