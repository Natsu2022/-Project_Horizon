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
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"vuln_assessment_app/internal/crawler"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/plugin"
	"vuln_assessment_app/internal/report"
	"vuln_assessment_app/internal/standards"
)

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
	plugins := make([]plugin.ScannerPlugin, 0, 6)

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
		plugins = append(plugins, &plugin.XSSScanner{})
	}
	if req.Options.SQLi {
		plugins = append(plugins, &plugin.SQLiScanner{})
	}
	if req.Options.CVE {
		plugins = append(plugins, &plugin.CVEScanner{})
	}
	if req.Options.BAC {
		plugins = append(plugins, &plugin.BACScanner{})
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
	started := time.Now()
	scanID := started.Format("20060102-150405")

	c := crawler.Crawler{
		StartURL: e.Request.Target,
		MaxPages: e.Request.MaxPages,
		MaxDepth: e.Request.MaxDepth,
	}
	urls := c.RunWithContext(ctx)

	var (
		mu       sync.Mutex
		findings = make([]model.Finding, 0)
		seen     = map[string]bool{}
		wg       sync.WaitGroup
		sem      = make(chan struct{}, workerCount)
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

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CVSSScore == findings[j].CVSSScore {
			return findings[i].Type < findings[j].Type
		}
		return findings[i].CVSSScore > findings[j].CVSSScore
	})

	stats := calculateStats(len(urls), findings)
	reports := report.GenerateArtifacts(scanID, e.Request.Target, findings, stats, e.Request.ReportFormats)

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
