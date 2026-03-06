package plugin

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
	BaseURL string
	APIKey  string
	once    sync.Once
	results []model.Finding
}

func (z *ZAPScanner) Name() string { return "zap" }

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
	base := strings.TrimRight(z.BaseURL, "/")

	log.Printf("[ZAPScanner] starting spider on %s", target)
	spiderID := z.startScan(ctx, client, base, "spider", target)
	if spiderID == "" {
		log.Println("[ZAPScanner] failed to start spider — is ZAP running?")
		return nil
	}
	if !z.waitScan(ctx, client, base, "spider", spiderID) {
		return nil
	}

	log.Printf("[ZAPScanner] starting active scan on %s", target)
	ascanID := z.startScan(ctx, client, base, "ascan", target)
	if ascanID == "" {
		log.Println("[ZAPScanner] failed to start active scan")
		return nil
	}
	if !z.waitScan(ctx, client, base, "ascan", ascanID) {
		return nil
	}

	return z.fetchAlerts(ctx, client, base, target)
}

// startScan triggers a ZAP spider or active scan and returns the scan ID.
func (z *ZAPScanner) startScan(ctx context.Context, client *http.Client, base, component, target string) string {
	endpoint := fmt.Sprintf("%s/JSON/%s/action/scan/?apikey=%s&url=%s",
		base, component, url.QueryEscape(z.APIKey), url.QueryEscape(target))
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

// fetchAlerts retrieves all ZAP alerts and converts them to model.Finding.
func (z *ZAPScanner) fetchAlerts(ctx context.Context, client *http.Client, base, target string) []model.Finding {
	endpoint := fmt.Sprintf("%s/JSON/core/view/alerts/?apikey=%s", base, url.QueryEscape(z.APIKey))
	body := z.getJSON(ctx, client, endpoint)
	if body == nil {
		return nil
	}
	var resp zapAlertsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Println("[ZAPScanner] failed to parse alerts:", err)
		return nil
	}

	findings := make([]model.Finding, 0, len(resp.Alerts))
	idx := 0
	for _, alert := range resp.Alerts {
		sev := zapRiskToSeverity(alert.RiskCode)
		if sev == "" {
			continue // skip Informational
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

	log.Printf("[ZAPScanner] %d findings from %d alerts", len(findings), len(resp.Alerts))
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
		return standards.A06VulnerableComponents, standards.A06URL
	default:
		return standards.A02SecurityMisconfiguration, standards.A02URL
	}
}
