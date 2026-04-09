package engine

// ─── Scanner Engine — Core Orchestrator ──────────────────────────────────────
//
// Receives: model.ScanRequest  (from api.ScanHandler)
// Returns:  model.ScanResponse (sent back to the GUI as JSON)
//
// Execution flow inside Run(ctx):
//
//   Step 1 — Crawl
//     Crawler.RunWithContext(ctx) → []model.URLInfo
//     Discovers all reachable pages on the target site (BFS, same-host only).
//
//   Step 2 — Parallel Scan
//     For each URLInfo, a goroutine is launched (max workerCount=10 concurrent).
//     Each goroutine calls every enabled Plugin.Scan(ctx, url) → []Finding.
//     RequestDelayMs sleep is applied before each goroutine to rate-limit.
//
//   Step 3 — Deduplicate
//     Findings with the same (Type|TargetURL|Evidence) key are discarded.
//     A mutex protects the shared findings slice.
//
//   Step 4 — Sort
//     Findings sorted by CVSSScore descending (highest severity first).
//     Ties broken alphabetically by Type.
//
//   Step 5 — Report Generation
//     report.GenerateArtifacts() writes JSON, HTML, and/or PDF files.
//     Paths returned as []ReportArtifact inside ScanResponse.
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"

	"vuln_assessment_app/internal/crawler"
	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/plugin"
	"vuln_assessment_app/internal/report"
	"vuln_assessment_app/internal/standards"
)

// ── Log capture ───────────────────────────────────────────────────────────────
// logCapture wraps an io.Writer (stderr) and intercepts lines that contain
// "[Engine]" or "[ZAPScanner]", storing them in a ring buffer so the GUI can
// poll GET /logs and display backend progress in real time.

const maxLogLines = 500

var (
	logMu   sync.Mutex
	logBuf  []string // ring buffer of captured backend log lines
)

// logCapture is a line-buffering io.Writer that feeds log.SetOutput().
type logCapture struct {
	out  io.Writer
	mu   sync.Mutex
	rest []byte // incomplete line from the previous Write
}

// NewLogCapture returns a writer suitable for log.SetOutput(). It passes every
// byte through to out (stderr) and additionally captures lines from [Engine]
// and [ZAPScanner] into the global ring buffer for GET /logs.
func NewLogCapture(out io.Writer) io.Writer { return &logCapture{out: out} }

func (lc *logCapture) Write(p []byte) (int, error) {
	lc.mu.Lock()
	lc.rest = append(lc.rest, p...)
	for {
		idx := bytes.IndexByte(lc.rest, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(lc.rest[:idx]), "\r")
		lc.rest = lc.rest[idx+1:]
		if strings.Contains(line, "[Engine]") || strings.Contains(line, "[ZAPScanner]") {
			appendBackendLog(line)
		}
	}
	lc.mu.Unlock()
	return lc.out.Write(p)
}

func appendBackendLog(line string) {
	logMu.Lock()
	defer logMu.Unlock()
	logBuf = append(logBuf, line)
	if len(logBuf) > maxLogLines {
		logBuf = logBuf[len(logBuf)-maxLogLines:]
	}
}

// GetLogs returns log lines added after index `after` and the new total count.
// The GUI calls GET /logs?after=N to retrieve only lines it has not seen yet.
func GetLogs(after int) ([]string, int) {
	logMu.Lock()
	defer logMu.Unlock()
	total := len(logBuf)
	if after >= total {
		return nil, total
	}
	result := make([]string, total-after)
	copy(result, logBuf[after:])
	return result, total
}

// ClearLogs empties the log buffer at the start of each scan.
func ClearLogs() {
	logMu.Lock()
	logBuf = nil
	logMu.Unlock()
}

// ── Global cancel ─────────────────────────────────────────────────────────────
// A single cancel function for the currently running scan, so POST /cancel can
// stop it immediately without waiting for the HTTP connection to close.

var (
	globalCancelMu sync.Mutex
	globalCancel   context.CancelFunc
)

// SetGlobalCancel stores cancel for the active scan. Called by ScanHandler.
func SetGlobalCancel(fn context.CancelFunc) {
	globalCancelMu.Lock()
	globalCancel = fn
	globalCancelMu.Unlock()
}

// CancelCurrentScan calls the stored cancel func (no-op if no scan is running).
// Called by the POST /cancel endpoint.
func CancelCurrentScan() {
	globalCancelMu.Lock()
	if globalCancel != nil {
		globalCancel()
	}
	globalCancelMu.Unlock()
}

// ── Progress tracking ─────────────────────────────────────────────────────────
// A single global progress state updated during Run() and read by GET /progress.

var (
	progressMu  sync.RWMutex
	curProgress = ScanProgress{Phase: "idle"}
)

// ScanProgress is the JSON payload returned by GET /progress.
type ScanProgress struct {
	Phase   string  `json:"phase"`   // "idle" | "crawling" | "scanning" | "reporting"
	Done    int     `json:"done"`    // URLs fully processed
	Total   int     `json:"total"`   // total URLs to scan
	Percent float64 `json:"percent"` // 0–100
}

// GetProgress returns a snapshot of the current scan progress (thread-safe).
func GetProgress() ScanProgress {
	progressMu.RLock()
	defer progressMu.RUnlock()
	return curProgress
}

func setProgress(phase string, done, total int) {
	var pct float64
	switch phase {
	case "crawling":
		pct = 5
	case "scanning":
		if total > 0 {
			pct = 10 + float64(done)/float64(total)*85
		} else {
			pct = 10
		}
	case "reporting":
		pct = 98
	default: // "idle"
		pct = 0
	}
	progressMu.Lock()
	curProgress = ScanProgress{Phase: phase, Done: done, Total: total, Percent: pct}
	progressMu.Unlock()
}

// workerCount controls how many URLs are scanned concurrently.
const workerCount = 10

type ScannerEngine struct {
	Request model.ScanRequest
	Plugins []plugin.ScannerPlugin
}

// NewEngine builds a ScannerEngine with only the plugins enabled by req.Options.
// Plugin instances are stateless (except ZAPScanner which uses sync.Once),
// so they can safely be called concurrently by multiple goroutines.
func NewEngine(req model.ScanRequest) *ScannerEngine {
	plugins := make([]plugin.ScannerPlugin, 0, 9)

	if req.Options.Headers {
		plugins = append(plugins, &plugin.HeaderScanner{})
	}
	if req.Options.Misconfig {
		plugins = append(plugins, &plugin.MisconfigScanner{})
	}
	if req.Options.TLS {
		plugins = append(plugins, &plugin.TLSScanner{})
	}
	if req.Options.XSS {
		plugins = append(plugins, &plugin.XSSScanner{FullScan: req.FullScanMode})
	}
	if req.Options.SQLi {
		plugins = append(plugins, &plugin.SQLiScanner{FullScan: req.FullScanMode})
	}
	if req.Options.CVE {
		plugins = append(plugins, &plugin.CVEScanner{})
	}
	if req.Options.BAC {
		plugins = append(plugins, &plugin.BACScanner{})
	}
	if req.Options.CMDi {
		plugins = append(plugins, &plugin.CMDiScanner{FullScan: req.FullScanMode})
	}
	if req.Options.ZAP {
		plugins = append(plugins, &plugin.ZAPScanner{
			BaseURL: req.ZAPBaseURL,
			APIKey:  req.ZAPAPIKey,
		})
	}

	return &ScannerEngine{Request: req, Plugins: plugins}
}

func (e *ScannerEngine) Run(ctx context.Context) model.ScanResponse {
	ClearLogs()
	defer setProgress("idle", 0, 0) // reset progress when Run() returns

	started := time.Now()
	scanID := started.Format("20060102-150405")

	// ── Auth: perform login and share session cookies with all scanner requests ──
	if e.Request.Auth.Enabled && e.Request.Auth.LoginURL != "" {
		jar := performLogin(e.Request.Auth)
		httpclient.SetSessionJar(jar)
		log.Println("[Engine] Auth: login complete, session cookies active")
	}
	defer httpclient.SetSessionJar(nil) // clear session after scan completes

	// ── Brute Force: try credential lists against the login endpoint ──────────
	var bfFindings []model.Finding
	if e.Request.BruteForce.Enabled {
		bfFindings = runBruteForce(ctx, e.Request.BruteForce, e.Request.Auth)
	}

	setProgress("crawling", 0, 0)
	c := crawler.Crawler{
		StartURL: e.Request.Target,
		MaxPages: e.Request.MaxPages,
		MaxDepth: e.Request.MaxDepth,
	}
	urls := c.RunWithContext(ctx)

	setProgress("scanning", 0, len(urls))

	var (
		mu       sync.Mutex
		findings = make([]model.Finding, 0)
		seen     = map[string]bool{}
		wg       sync.WaitGroup
		sem      = make(chan struct{}, workerCount)
		doneCnt  int64
	)

	for _, u := range urls {
		if ctx.Err() != nil {
			log.Println("[Engine] canceled")
			break
		}
		if e.Request.RequestDelayMs > 0 {
			time.Sleep(time.Duration(e.Request.RequestDelayMs) * time.Millisecond)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u model.URLInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				n := atomic.AddInt64(&doneCnt, 1)
				setProgress("scanning", int(n), len(urls))
			}()

			local := make([]model.Finding, 0)
			for _, p := range e.Plugins {
				if ctx.Err() != nil {
					break
				}
				log.Printf("[Engine] %s -> %s", p.Name(), u.URL)
				local = append(local, p.Scan(ctx, u)...)
			}

			mu.Lock()
			for _, f := range local {
				key := f.Type + "|" + f.TargetURL + "|" + f.Evidence
				if !seen[key] {
					seen[key] = true
					findings = append(findings, f)
				}
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	// Merge brute-force findings (collected before crawl, deduplicated separately).
	findings = append(findings, bfFindings...)

	setProgress("reporting", len(urls), len(urls))

	// Step 4a — Compute dynamic RiskScore per finding (OWASP-inspired formula).
	// Must run after deduplication so occurrence counts and incidence rates are final.
	findings = calcRiskScores(findings, len(urls))

	// Step 4b — Sort by RiskScore descending; break ties by CVSSScore, then Type.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		if findings[i].CVSSScore != findings[j].CVSSScore {
			return findings[i].CVSSScore > findings[j].CVSSScore
		}
		return findings[i].Type < findings[j].Type
	})

	stats := calculateStats(len(urls), findings)
	reports := report.GenerateArtifacts(scanID, e.Request.Target, findings, stats, e.Request.ReportFormats)

	// If ZAPScanner produced its own HTML report, save it as an additional artifact.
	for _, p := range e.Plugins {
		if zapPlugin, ok := p.(*plugin.ZAPScanner); ok && len(zapPlugin.ReportHTML) > 0 {
			zapPath := filepath.Join("reports", scanID, "zap_report.html")
			if err := os.WriteFile(zapPath, zapPlugin.ReportHTML, 0o644); err == nil {
				abs, _ := filepath.Abs(zapPath)
				reports = append(reports, model.ReportArtifact{Format: "zap_html", Path: abs})
				log.Printf("[Engine] ZAP HTML report saved: %s", abs)
			} else {
				log.Printf("[Engine] failed to save ZAP HTML report: %v", err)
			}
			break
		}
	}

	return model.ScanResponse{
		OWASP:      standards.OWASPTop10Version,
		ScanID:     scanID,
		Target:     e.Request.Target,
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: time.Now().Format(time.RFC3339),
		Stats:      stats,
		Findings:   findings,
		Reports:    reports,
	}
}

// performLogin fetches auth.LoginURL, auto-detects login form fields and hidden
// CSRF inputs, then POSTs the credentials to the form's action URL.
//
// Detection priority for UsernameField:
//   1. Explicit value in auth.UsernameField
//   2. <input type="email"> found in the form
//   3. <input> whose name contains: email, user, login, account, identifier
//
// Detection priority for PasswordField:
//   1. Explicit value in auth.PasswordField
//   2. <input type="password"> found in the form
func performLogin(auth model.AuthConfig) http.CookieJar {
	jar := httpclient.NewCookieJar()
	client := &http.Client{
		Timeout:   15 * time.Second,
		Jar:       jar,
		Transport: &http.Transport{ForceAttemptHTTP2: false},
	}

	// Step 1: GET login page and parse the form.
	actionURL := auth.LoginURL
	formFields := url.Values{}

	if pageResp, err := client.Get(auth.LoginURL); err == nil {
		body, _ := io.ReadAll(io.LimitReader(pageResp.Body, 512*1024))
		pageResp.Body.Close()

		if lf := detectLoginForm(body, auth.LoginURL); lf != nil {
			if lf.actionURL != "" {
				actionURL = lf.actionURL
			}
			// Include hidden fields (CSRF tokens, nonces, etc.).
			for k, v := range lf.hiddenFields {
				formFields.Set(k, v)
			}
			// Auto-fill field names only when not explicitly configured.
			if auth.UsernameField == "" && lf.usernameField != "" {
				auth.UsernameField = lf.usernameField
				log.Printf("[Engine] Auth: detected username field=%q", auth.UsernameField)
			}
			if auth.PasswordField == "" && lf.passwordField != "" {
				auth.PasswordField = lf.passwordField
				log.Printf("[Engine] Auth: detected password field=%q", auth.PasswordField)
			}
		} else {
			log.Printf("[Engine] Auth: no login form detected on page, using configured field names")
		}
	} else {
		log.Printf("[Engine] Auth: failed to fetch login page: %v", err)
	}

	if auth.UsernameField == "" {
		auth.UsernameField = "username"
	}
	if auth.PasswordField == "" {
		auth.PasswordField = "password"
	}

	// Step 2: POST credentials + hidden fields to the form action URL.
	formFields.Set(auth.UsernameField, auth.Username)
	formFields.Set(auth.PasswordField, auth.Password)

	postResp, err := client.PostForm(actionURL, formFields)
	if err != nil {
		log.Printf("[Engine] Auth: login POST failed: %v", err)
		return jar
	}
	io.Copy(io.Discard, postResp.Body)
	postResp.Body.Close()

	u, _ := url.Parse(actionURL)
	log.Printf("[Engine] Auth: login POST %s → %d (cookies=%d)",
		actionURL, postResp.StatusCode, len(jar.Cookies(u)))
	return jar
}

// loginForm holds parsed details of an HTML login form.
type loginForm struct {
	actionURL     string
	usernameField string
	passwordField string
	hiddenFields  map[string]string
}

// detectLoginForm parses pageBody for the first <form> that contains a password
// input. Resolves relative action URLs against pageURL. Returns nil if not found.
func detectLoginForm(pageBody []byte, pageURL string) *loginForm {
	doc, err := html.Parse(bytes.NewReader(pageBody))
	if err != nil {
		return nil
	}
	base, _ := url.Parse(pageURL)

	var found *loginForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if found != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			if f := parseFormNode(n, base); f.passwordField != "" {
				found = f
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return found
}

// parseFormNode extracts the action URL, input field names, and hidden values
// from a single <form> node.
func parseFormNode(formNode *html.Node, base *url.URL) *loginForm {
	f := &loginForm{hiddenFields: map[string]string{}}

	for _, a := range formNode.Attr {
		if a.Key == "action" && a.Val != "" {
			if ref, err := url.Parse(a.Val); err == nil {
				f.actionURL = base.ResolveReference(ref).String()
			}
		}
	}
	if f.actionURL == "" {
		f.actionURL = base.String()
	}

	var walkInputs func(*html.Node)
	walkInputs = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			am := htmlAttrs(n.Attr)
			typ := strings.ToLower(am["type"])
			name := am["name"]
			switch typ {
			case "password":
				if f.passwordField == "" && name != "" {
					f.passwordField = name
				}
			case "hidden":
				if name != "" {
					f.hiddenFields[name] = am["value"]
				}
			case "email":
				if f.usernameField == "" && name != "" {
					f.usernameField = name
				}
			default: // text, tel, number — match by name keywords
				if f.usernameField == "" && name != "" {
					lname := strings.ToLower(name)
					for _, kw := range []string{"email", "user", "login", "account", "identifier", "credential"} {
						if strings.Contains(lname, kw) {
							f.usernameField = name
							break
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(formNode)
	return f
}

// htmlAttrs converts []html.Attribute to a key→value map.
func htmlAttrs(attrs []html.Attribute) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Val
	}
	return m
}

// ── Brute Force ───────────────────────────────────────────────────────────────

// runBruteForce tries every username × password combination against the login
// form. It auto-detects form fields once, then calls tryLogin() per pair.
// Successful logins produce Critical findings (A07:2025 / CWE-521, CWE-307).
func runBruteForce(ctx context.Context, bf model.BruteForceConfig, auth model.AuthConfig) []model.Finding {
	loginURL := bf.LoginURL
	if loginURL == "" {
		loginURL = auth.LoginURL
	}
	if loginURL == "" {
		log.Printf("[Engine] BruteForce: no login_url configured, skipping")
		return nil
	}

	log.Printf("[Engine] BruteForce: starting against %s (%d users × %d passwords)",
		loginURL, len(bf.Usernames), len(bf.Passwords))

	// Detect form fields once from a single GET (reused by every attempt).
	usernameField := bf.UsernameField
	passwordField := bf.PasswordField
	if tempClient := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: false}}); true {
		if resp, err := tempClient.Get(loginURL); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			if lf := detectLoginForm(body, loginURL); lf != nil {
				if usernameField == "" && lf.usernameField != "" {
					usernameField = lf.usernameField
					log.Printf("[Engine] BruteForce: detected username field=%q", usernameField)
				}
				if passwordField == "" && lf.passwordField != "" {
					passwordField = lf.passwordField
					log.Printf("[Engine] BruteForce: detected password field=%q", passwordField)
				}
			}
		}
	}
	if usernameField == "" {
		usernameField = "username"
	}
	if passwordField == "" {
		passwordField = "password"
	}

	delayMs := bf.DelayMs
	if delayMs < 100 {
		delayMs = 100
	}
	maxAttempts := bf.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 100
	}

	var findings []model.Finding
	attempts := 0

outer:
	for _, username := range bf.Usernames {
		for _, password := range bf.Passwords {
			if ctx.Err() != nil {
				log.Printf("[Engine] BruteForce: cancelled after %d attempts", attempts)
				break outer
			}
			if attempts >= maxAttempts {
				log.Printf("[Engine] BruteForce: max attempts (%d) reached", maxAttempts)
				break outer
			}
			attempts++
			log.Printf("[Engine] BruteForce: attempt %d — user=%s", attempts, username)

			if ok, finalURL := tryLogin(loginURL, usernameField, passwordField, username, password); ok {
				log.Printf("[Engine] BruteForce: SUCCESS user=%s at %s", username, finalURL)
				evidence := fmt.Sprintf("Username: %s | Password: %s | Final URL: %s",
					username, password, finalURL)
				f := model.NewFinding(
					"bruteforce", "credential_found",
					"Weak Credentials Found via Brute Force",
					"The application accepted a credential pair discovered through automated testing, "+
						"indicating weak or default credentials are in use.",
					"Critical",
					standards.A07AuthFailures,
					loginURL,
					evidence,
					"Enforce strong password policies, account lockout after repeated failures, "+
						"and multi-factor authentication.",
					standards.A07URL,
				)
				f.CWEIDs = []string{"CWE-521", "CWE-307"}
				findings = append(findings, f)
				if bf.StopOnSuccess {
					break outer
				}
			}
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	log.Printf("[Engine] BruteForce: finished — %d attempts, %d credentials found", attempts, len(findings))
	return findings
}

// tryLogin creates a fresh HTTP client + cookie jar, GETs the login page to
// obtain a fresh CSRF token, then POSTs the credential pair.
// Returns (true, finalURL) on success, (false, "") otherwise.
func tryLogin(loginURL, usernameField, passwordField, username, password string) (bool, string) {
	jar := httpclient.NewCookieJar()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Jar:       jar,
		Transport: &http.Transport{ForceAttemptHTTP2: false},
	}

	actionURL := loginURL
	formFields := url.Values{}

	if pageResp, err := client.Get(loginURL); err == nil {
		body, _ := io.ReadAll(io.LimitReader(pageResp.Body, 256*1024))
		pageResp.Body.Close()
		if lf := detectLoginForm(body, loginURL); lf != nil {
			if lf.actionURL != "" {
				actionURL = lf.actionURL
			}
			for k, v := range lf.hiddenFields {
				formFields.Set(k, v)
			}
		}
	}

	formFields.Set(usernameField, username)
	formFields.Set(passwordField, password)

	postResp, err := client.PostForm(actionURL, formFields)
	if err != nil {
		return false, ""
	}
	body, _ := io.ReadAll(io.LimitReader(postResp.Body, 256*1024))
	postResp.Body.Close()

	finalURL := postResp.Request.URL.String()
	return detectLoginSuccess(jar, loginURL, finalURL, body), finalURL
}

// detectLoginSuccess uses three heuristics to decide if a POST login succeeded:
//  1. Failure keywords in the response body → definite failure.
//  2. Final URL path differs from login URL path → redirect to dashboard → success.
//  3. A session-related cookie was set in the jar → success.
func detectLoginSuccess(jar http.CookieJar, loginURL, finalURL string, body []byte) bool {
	bodyLower := strings.ToLower(string(body))
	failKeywords := []string{
		"invalid password", "invalid credential", "wrong password",
		"incorrect password", "login failed", "authentication failed",
		"bad credentials", "invalid username", "user not found",
		"account not found", "incorrect login",
	}
	for _, kw := range failKeywords {
		if strings.Contains(bodyLower, kw) {
			return false
		}
	}

	base, _ := url.Parse(loginURL)
	final, _ := url.Parse(finalURL)
	if base != nil && final != nil && final.Path != "" && final.Path != base.Path {
		return true
	}

	u, _ := url.Parse(loginURL)
	if u != nil {
		sessionKW := []string{"session", "auth", "access", "token", "jwt", "sid", "logged", "user"}
		for _, c := range jar.Cookies(u) {
			name := strings.ToLower(c.Name)
			for _, kw := range sessionKW {
				if strings.Contains(name, kw) {
					return true
				}
			}
		}
	}
	return false
}

// calcRiskScores computes a dynamic RiskScore for every finding using an
// OWASP-inspired formula adapted for single-target scans.
//
// Formula (max 340 pts):
//
//	RiskScore = (IncidenceRate% × 0.30)   // % of scanned URLs affected
//	          + (ExploitScore  × 10.0)    // how easy to exploit (0-10)
//	          + (ImpactScore   × 20.0)    // technical damage (0-10), weight ×2 like OWASP
//	          + (OccurrenceRatio × 10.0)  // volume tiebreaker (occurrences / totalURLs)
//
// All findings of the same Title share the same RiskScore so that the sort
// order groups them consistently.
func calcRiskScores(findings []model.Finding, totalURLs int) []model.Finding {
	if totalURLs == 0 || len(findings) == 0 {
		return findings
	}

	// Count occurrences and unique URLs affected per finding title.
	type titleStats struct {
		occurrences  int
		urlsAffected map[string]struct{}
	}
	byTitle := map[string]*titleStats{}
	for _, f := range findings {
		ts, ok := byTitle[f.Title]
		if !ok {
			ts = &titleStats{urlsAffected: map[string]struct{}{}}
			byTitle[f.Title] = ts
		}
		ts.occurrences++
		ts.urlsAffected[f.TargetURL] = struct{}{}
	}

	// Pre-compute RiskScore per title.
	scoreByTitle := map[string]float64{}
	for title, ts := range byTitle {
		incidenceRate := float64(len(ts.urlsAffected)) / float64(totalURLs) * 100.0
		occRatio := float64(ts.occurrences) / float64(totalURLs)

		// Use Exploit/Impact from the first finding with this title (all share same severity).
		var exploit, impact float64
		for _, f := range findings {
			if f.Title == title {
				exploit = f.ExploitScore
				impact = f.ImpactScore
				break
			}
		}

		risk := (incidenceRate * 0.30) + (exploit * 10.0) + (impact * 20.0) + (occRatio * 10.0)
		// Round to 2 decimal places.
		scoreByTitle[title] = float64(int(risk*100+0.5)) / 100.0
	}

	// Assign computed RiskScore back to each finding.
	for i := range findings {
		findings[i].RiskScore = scoreByTitle[findings[i].Title]
	}
	return findings
}

// calculateStats counts findings by severity and packages them with the
// total number of scanned URLs into a ScanStats for the response.
func calculateStats(scannedURLs int, findings []model.Finding) model.ScanStats {
	stats := model.ScanStats{ScannedURLs: scannedURLs, TotalFindings: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			stats.CriticalFindings++
		case "High":
			stats.HighFindings++
		case "Medium":
			stats.MediumFindings++
		case "Low":
			stats.LowFindings++
		}
	}
	return stats
}
