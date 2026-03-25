package crawler

// ─── BFS Web Crawler ──────────────────────────────────────────────────────────
//
// Receives: Crawler{StartURL, MaxPages, MaxDepth}
// Returns:  []model.URLInfo  (URL + depth for every page discovered)
//
// Algorithm: Breadth-First Search (BFS) over the target site.
//   1. Enqueue StartURL at depth 0.
//   2. Dequeue next node, fetch its HTML, extract all href= links via regex.
//   3. Skip external links (different hostname), mailto:, javascript:.
//   4. Normalise URLs (strip plain #anchors, session/token query params).
//   5. Enqueue unvisited same-host links at depth+1.
//   6. Stop when MaxPages results are collected or MaxDepth is exceeded.
//
// SPA support (hash-based routing):
//   href="#/route" links (Angular/Vue HashRouter / React HashRouter) are
//   detected via hashRouteRegex. These routes are added to results directly
//   without re-crawling — the server returns the same HTML for all hash routes,
//   so crawling them further would be redundant and could cause infinite loops.
//
// Output goes to: engine.ScannerEngine, which passes each URLInfo to all
// enabled plugins for vulnerability scanning.
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
)

// hrefRegex matches regular href values (excludes hash-only hrefs).
var hrefRegex = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)

// hashRouteRegex matches SPA hash-based routes: href="#/route/path"
// Covers Angular, Vue HashRouter, React HashRouter patterns.
var hashRouteRegex = regexp.MustCompile(`(?i)href=["'](#/[^"']*)["']`)

type Crawler struct {
	StartURL string
	MaxPages int
	MaxDepth int
}

type crawlNode struct {
	url   string
	depth int
}

func (c *Crawler) Run() []model.URLInfo {
	return c.RunWithContext(context.Background())
}

func (c *Crawler) RunWithContext(ctx context.Context) []model.URLInfo {
	start := httpclient.EnsureURLScheme(c.StartURL)
	startParsed, err := url.Parse(start)
	if err != nil {
		log.Println("[Crawler] Invalid start URL:", err)
		return nil
	}

	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = 30
	}
	maxDepth := c.MaxDepth
	if maxDepth < 0 {
		maxDepth = 0
	}

	queue := []crawlNode{{url: start, depth: 0}}
	visited := map[string]bool{}
	results := make([]model.URLInfo, 0, maxPages)

	for len(queue) > 0 && len(results) < maxPages {
		if ctx.Err() != nil {
			log.Println("[Crawler] canceled")
			return results
		}

		node := queue[0]
		queue = queue[1:]

		normalized := normalizeURL(node.url)
		if visited[normalized] {
			continue
		}
		visited[normalized] = true

		results = append(results, model.URLInfo{URL: node.url, Depth: node.depth})
		if node.depth >= maxDepth {
			continue
		}

		links := fetchLinks(ctx, node.url)
		for _, link := range links {
			abs := toAbsoluteURL(node.url, link)
			if abs == "" {
				continue
			}
			if !sameHost(startParsed, abs) {
				continue
			}
			key := normalizeURL(abs)
			if visited[key] {
				continue
			}

			if isSPAHashRoute(abs) {
				// SPA hash route: add directly to results without crawling.
				// The server returns the same HTML for all /#/... routes,
				// so there is nothing new to discover by making an HTTP request.
				visited[key] = true
				if len(results) < maxPages {
					results = append(results, model.URLInfo{URL: abs, Depth: node.depth + 1})
				}
			} else {
				queue = append(queue, crawlNode{url: abs, depth: node.depth + 1})
			}
		}
	}

	return results
}

// fetchLinks fetches the HTML at rawURL and returns all href= link values found,
// including SPA hash routes (href="#/..."). Skips javascript: and mailto: schemes.
// Returns nil on HTTP 4xx/5xx or network error.
func fetchLinks(ctx context.Context, rawURL string) []string {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, rawURL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	links := make([]string, 0)

	// Regular href links (no # prefix)
	for _, m := range hrefRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" || strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "mailto:") {
			continue
		}
		links = append(links, v)
	}

	// SPA hash-route links: href="#/route"
	for _, m := range hashRouteRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) >= 2 {
			links = append(links, m[1]) // e.g. "#/dashboard"
		}
	}

	return links
}

// isSPAHashRoute returns true if rawURL contains a hash fragment that starts
// with "/" — the convention used by Angular, Vue HashRouter, and React HashRouter.
func isSPAHashRoute(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasPrefix(u.Fragment, "/")
}

func toAbsoluteURL(baseRaw, candidate string) string {
	base, err := url.Parse(baseRaw)
	if err != nil {
		return ""
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(u)
	return resolved.String()
}

func sameHost(start *url.URL, candidate string) bool {
	u, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return strings.EqualFold(start.Hostname(), u.Hostname())
}

// normalizeURL removes plain URL anchors (#section) and session/token query params
// to avoid counting the same logical page as multiple distinct URLs.
// SPA hash routes (fragment starts with "/") are preserved for deduplication.
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// Keep SPA hash routes (/#/path); strip plain anchors (#section)
	if !strings.HasPrefix(u.Fragment, "/") {
		u.Fragment = ""
	}
	q := u.Query()
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "session") || strings.Contains(lk, "token") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return strings.TrimRight(u.String(), "/")
}
