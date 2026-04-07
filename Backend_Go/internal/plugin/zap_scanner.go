package plugin

// ─── ZAPScanner — OWASP ZAP Integration (Multi-category) ─────────────────────
//
// Receives: URLInfo (only processes Depth==0; all deeper URLs return nil)
// Does:     Calls a running OWASP ZAP daemon via its REST API.
// Returns:  []Finding  (one per ZAP alert instance)
//
// Prerequisites:
//   - OWASP ZAP must be running with API enabled (default: http://localhost:8880)
//   - ZAPBaseURL and ZAPAPIKey are configured in ScanRequest / GUI settings.
//
// Execution sequence (runs exactly ONCE per engine run via sync.Once):
//   1. Spider scan  — ZAP crawls the target (waits until status="100").
//   2. Active scan  — ZAP attacks the crawled URLs (waits until status="100").
//   3. Fetch alerts — retrieves all alerts via /JSON/core/view/alerts/.
//   4. Convert      — maps each ZAP alert (+ instances) to model.Finding.
//
// Alert conversion:
//   - RiskCode "3"→High, "2"→Medium, "1"→Low; "0"/Informational is skipped.
//   - OWASP category is inferred from the alert name via keyword matching
//     (inject/xss → A05, access control/path traversal → A01, tls → A04, etc.)
//   - Alerts without specific instances produce one finding for the target URL.
//
// OWASP: varies by alert (A01/A02/A03/A04/A05/A07 depending on ZAP's findings)
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

// zapCommonPorts lists ZAP daemon ports probed (in order) when no BaseURL is given.
var zapCommonPorts = []int{8080, 8880, 8090, 8443}

// ZAP API response types
type zapScanResp struct {
	Scan string `json:"scan"`
}

type zapStatusResp struct {
	Status string `json:"status"`
}

type zapAlertsResp struct {
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	Alert     string        `json:"alert"`
	Desc      string        `json:"desc"`
	RiskCode  string        `json:"riskcode"` // "3"=High "2"=Medium "1"=Low "0"=Info
	CWEID     string        `json:"cweid"`
	Instances []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
	Attack   string `json:"attack"`
}

// ZAPScanner calls a running OWASP ZAP daemon via its REST API.
// It runs Spider + Active Scan on the seed URL (Depth == 0) exactly once per engine run.
type ZAPScanner struct {
	BaseURL    string
	APIKey     string
	once       sync.Once
	results    []model.Finding
	ReportHTML []byte // raw HTML from /OTHER/core/other/htmlreport/ — saved by the engine
}

func (z *ZAPScanner) Name() string { return "zap" }

// checkZAPHealth pings /JSON/core/view/version/ to verify ZAP is reachable at base.
// Uses a 3-second probe timeout independent of the scan context.
func (z *ZAPScanner) checkZAPHealth(client *http.Client, base string) bool {
	probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf("%s/JSON/core/view/version/?apikey=%s", base, url.QueryEscape(z.APIKey))
	body := z.getJSON(probeCtx, client, endpoint)
	return body != nil && strings.Contains(string(body), "version")
}

// resolveBaseURL returns the first ZAP base URL that passes the health check.
// If z.BaseURL is non-empty it is verified first; on failure zapCommonPorts
// are probed in order. Returns "" when no reachable ZAP instance is found.
func (z *ZAPScanner) resolveBaseURL(client *http.Client) string {
	configured := strings.TrimRight(z.BaseURL, "/")
	candidates := []string{}
	if configured != "" {
		candidates = append(candidates, configured)
	}
	for _, port := range zapCommonPorts {
		candidate := fmt.Sprintf("http://localhost:%d", port)
		if candidate != configured {
			candidates = append(candidates, candidate)
		}
	}
	for _, base := range candidates {
		if z.checkZAPHealth(client, base) {
			if base != configured {
				log.Printf("[ZAPScanner] auto-detected ZAP at %s", base)
			} else {
				log.Printf("[ZAPScanner] ZAP confirmed at %s", base)
			}
			return base
		}
	}
	return ""
}

func (z *ZAPScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	if u.Depth != 0 {
		return nil
	}
	z.once.Do(func() {
		z.results = z.runZAPScan(ctx, u.URL)
	})
	return z.results
}

func (z *ZAPScanner) runZAPScan(ctx context.Context, target string) []model.Finding {
	client := &http.Client{Timeout: 15 * time.Second}

	// Step 0 — Auto-detect ZAP port (probe configured URL first, then common ports)
	base := z.resolveBaseURL(client)
	if base == "" {
		log.Println("[ZAPScanner] no reachable ZAP daemon found on any common port — is ZAP running?")
		return nil
	}

	// Step 1 — Traditional spider (fast; works for standard HTML sites)
	log.Printf("[ZAPScanner] step 1/4 traditional spider on %s", target)
	spiderID := z.startScan(ctx, client, base, "spider", target, "")
	if spiderID == "" {
		log.Println("[ZAPScanner] failed to start spider")
		return nil
	}
	if !z.waitScan(ctx, client, base, "spider", spiderID) {
		return nil
	}

	// Step 2 — AJAX spider (uses a real browser; discovers JS-rendered content
	// in Angular / React / Vue SPAs that the traditional spider misses)
	log.Printf("[ZAPScanner] step 2/4 AJAX spider on %s", target)
	if !z.runAjaxSpider(ctx, client, base, target) {
		// AJAX spider is optional — older ZAP versions or missing browser
		// add-on will fail here; we continue to active scan anyway.
		log.Println("[ZAPScanner] AJAX spider unavailable or failed — continuing without it")
	}

	// Step 3 — Active scan (attack phase); recurse=true covers all URLs ZAP
	// discovered during the spider phase, not just the seed URL.
	log.Printf("[ZAPScanner] step 3/4 active scan on %s", target)
	ascanID := z.startScan(ctx, client, base, "ascan", target, "&recurse=true&inScopeOnly=false")
	if ascanID == "" {
		log.Println("[ZAPScanner] failed to start active scan")
		return nil
	}
	if !z.waitScan(ctx, client, base, "ascan", ascanID) {
		return nil
	}

	// Step 4 — Collect alerts
	log.Printf("[ZAPScanner] step 4/5 fetching alerts")
	findings := z.fetchAlerts(ctx, client, base, target)

	// Step 5 — Download ZAP's own HTML report for inclusion as a report artifact
	log.Printf("[ZAPScanner] step 5/5 downloading ZAP HTML report")
	z.ReportHTML = z.fetchZAPReport(ctx, client, base)
	if len(z.ReportHTML) == 0 {
		log.Println("[ZAPScanner] ZAP HTML report unavailable — skipping")
	}

	return findings
}

// fetchZAPReport downloads ZAP's built-in HTML report from /OTHER/core/other/htmlreport/.
// Uses /OTHER/ prefix so ZAP returns raw HTML instead of a JSON wrapper.
func (z *ZAPScanner) fetchZAPReport(ctx context.Context, client *http.Client, base string) []byte {
	endpoint := fmt.Sprintf("%s/OTHER/core/other/htmlreport/?apikey=%s",
		base, url.QueryEscape(z.APIKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return body
}

// runAjaxSpider starts ZAP's AJAX spider and waits until it stops.
//
// The AJAX spider opens a real (headless) browser session managed by ZAP,
// clicks links, and submits forms — allowing it to discover URLs that only
// appear after JavaScript execution (Angular, React, Vue SPAs).
//
// Status values returned by /JSON/ajaxSpider/view/status/:
//
//	"running" — still crawling
//	"stopped"  — finished (timeout reached or no new URLs found)
//
// A hard cap of 2 minutes is enforced; if ZAP has not finished by then
// a stop command is sent and the function returns true so scanning continues.
//
// Returns false if the AJAX spider add-on is not installed or the request
// fails; the caller should treat this as a non-fatal condition.
func (z *ZAPScanner) runAjaxSpider(ctx context.Context, client *http.Client, base, target string) bool {
	// Start the AJAX spider
	startEP := fmt.Sprintf("%s/JSON/ajaxSpider/action/scan/?apikey=%s&url=%s",
		base, url.QueryEscape(z.APIKey), url.QueryEscape(target))
	body := z.getJSON(ctx, client, startEP)
	if body == nil || !strings.Contains(string(body), "OK") {
		return false
	}

	// Poll every 5 s until status == "stopped", 2-minute cap, or context cancelled
	statusEP := fmt.Sprintf("%s/JSON/ajaxSpider/view/status/?apikey=%s",
		base, url.QueryEscape(z.APIKey))
	stopEP := fmt.Sprintf("%s/JSON/ajaxSpider/action/stop/?apikey=%s",
		base, url.QueryEscape(z.APIKey))

	deadline := time.Now().Add(2 * time.Minute)

	for {
		if ctx.Err() != nil {
			z.getJSON(ctx, client, stopEP) // best-effort stop
			return false
		}
		if time.Now().After(deadline) {
			log.Println("[ZAPScanner] ajaxSpider: 2-minute timeout reached — stopping")
			z.getJSON(ctx, client, stopEP)
			return true
		}
		statusBody := z.getJSON(ctx, client, statusEP)
		if statusBody != nil {
			var st struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(statusBody, &st); err == nil {
				log.Printf("[ZAPScanner] ajaxSpider: %s", st.Status)
				if st.Status == "stopped" {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			z.getJSON(ctx, client, stopEP)
			return false
		case <-time.After(5 * time.Second):
		}
	}
}

// startScan triggers a ZAP spider or active scan and returns the scan ID.
// extraParams is appended verbatim to the query string (e.g. "&recurse=true&inScopeOnly=false").
func (z *ZAPScanner) startScan(ctx context.Context, client *http.Client, base, component, target, extraParams string) string {
	endpoint := fmt.Sprintf("%s/JSON/%s/action/scan/?apikey=%s&url=%s%s",
		base, component, url.QueryEscape(z.APIKey), url.QueryEscape(target), extraParams)
	body := z.getJSON(ctx, client, endpoint)
	if body == nil {
		return ""
	}
	var resp zapScanResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return resp.Scan
}

// waitScan polls the scan status every 5 seconds until 100% or context cancelled.
func (z *ZAPScanner) waitScan(ctx context.Context, client *http.Client, base, component, scanID string) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		endpoint := fmt.Sprintf("%s/JSON/%s/view/status/?apikey=%s&scanId=%s",
			base, component, url.QueryEscape(z.APIKey), scanID)
		body := z.getJSON(ctx, client, endpoint)
		if body != nil {
			var resp zapStatusResp
			if err := json.Unmarshal(body, &resp); err == nil {
				log.Printf("[ZAPScanner] %s: %s%%", component, resp.Status)
				if resp.Status == "100" {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
		}
	}
}

// fetchAlerts retrieves all ZAP alerts using /JSON/alert/view/alerts/ with pagination
// and converts them to model.Finding. Pages of 5 000 are fetched until exhausted.
func (z *ZAPScanner) fetchAlerts(ctx context.Context, client *http.Client, base, target string) []model.Finding {
	const pageSize = 5000
	allAlerts := make([]zapAlert, 0)
	for start := 0; ; start += pageSize {
		endpoint := fmt.Sprintf(
			"%s/JSON/alert/view/alerts/?apikey=%s&baseurl=%s&start=%d&count=%d",
			base, url.QueryEscape(z.APIKey), url.QueryEscape(target), start, pageSize,
		)
		body := z.getJSON(ctx, client, endpoint)
		if body == nil {
			break
		}
		var page zapAlertsResp
		if err := json.Unmarshal(body, &page); err != nil {
			log.Println("[ZAPScanner] failed to parse alerts:", err)
			break
		}
		allAlerts = append(allAlerts, page.Alerts...)
		if len(page.Alerts) < pageSize {
			break // last page reached
		}
	}
	resp := zapAlertsResp{Alerts: allAlerts}

	log.Printf("[ZAPScanner] raw alerts from ZAP: %d total", len(resp.Alerts))
	infoSkipped := 0
	findings := make([]model.Finding, 0, len(resp.Alerts))
	idx := 0
	for _, alert := range resp.Alerts {
		sev := zapRiskToSeverity(alert.RiskCode)
		if sev == "" {
			infoSkipped++
			continue // skip Informational (riskcode=0)
		}
		owasp, owaspURL := zapOWASPCategory(alert.Alert)

		instances := alert.Instances
		if len(instances) == 0 {
			// No specific instance — create one finding for the target itself
			f := model.NewFinding(
				"zap",
				"zap_"+strings.ToLower(strings.ReplaceAll(alert.Alert, " ", "_")),
				alert.Alert,
				alert.Desc,
				sev,
				owasp,
				target,
				"ZAP alert (no specific instance)",
				"Refer to ZAP documentation and OWASP guidelines for remediation.",
				owaspURL+" | https://www.zaproxy.org/",
			)
			f.ID = buildID("ZAP", target, idx)
			findings = append(findings, f)
			idx++
			continue
		}

		for _, inst := range instances {
			evidence := inst.Attack
			if evidence == "" {
				evidence = inst.Evidence
			}
			if evidence == "" {
				evidence = "param: " + inst.Param
			}
			uri := inst.URI
			if uri == "" {
				uri = target
			}
			f := model.NewFinding(
				"zap",
				"zap_"+strings.ToLower(strings.ReplaceAll(alert.Alert, " ", "_")),
				alert.Alert,
				alert.Desc,
				sev,
				owasp,
				uri,
				evidence,
				"Refer to ZAP documentation and OWASP guidelines for remediation.",
				owaspURL+" | https://www.zaproxy.org/",
			)
			f.ID = buildID("ZAP", uri, idx)
			findings = append(findings, f)
			idx++
		}
	}

	log.Printf("[ZAPScanner] %d findings from %d alerts (%d informational skipped)",
		len(findings), len(resp.Alerts), infoSkipped)
	return findings
}

// getJSON performs a GET request and returns the body bytes, or nil on error.
func (z *ZAPScanner) getJSON(ctx context.Context, client *http.Client, rawURL string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return body
}

// zapRiskToSeverity maps ZAP riskcode string to our severity strings.
func zapRiskToSeverity(code string) string {
	switch code {
	case "3":
		return "High"
	case "2":
		return "Medium"
	case "1":
		return "Low"
	default:
		return "" // skip Informational (0) and unknown
	}
}

// zapOWASPCategory maps ZAP alert names to OWASP Top 10:2025 categories via keyword matching.
func zapOWASPCategory(alertName string) (string, string) {
	name := strings.ToLower(alertName)
	switch {
	case strings.Contains(name, "inject") || strings.Contains(name, "xss") ||
		strings.Contains(name, "cross-site scripting") || strings.Contains(name, "sql"):
		return standards.A05Injection, standards.A05URL
	case strings.Contains(name, "access control") || strings.Contains(name, "path traversal") ||
		strings.Contains(name, "directory listing") || strings.Contains(name, "idor"):
		return standards.A01BrokenAccessControl, standards.A01URL
	case strings.Contains(name, "tls") || strings.Contains(name, "ssl") ||
		strings.Contains(name, "certificate") || strings.Contains(name, "crypto"):
		return standards.A04CryptographicFailures, standards.A04URL
	case strings.Contains(name, "auth") || strings.Contains(name, "session") ||
		strings.Contains(name, "login") || strings.Contains(name, "password"):
		return standards.A07AuthFailures, standards.A07URL
	case strings.Contains(name, "component") || strings.Contains(name, "library") ||
		strings.Contains(name, "outdated") || strings.Contains(name, "version"):
		return standards.A03SupplyChainFailures, standards.A03URL
	default:
		return standards.A02SecurityMisconfiguration, standards.A02URL
	}
}
