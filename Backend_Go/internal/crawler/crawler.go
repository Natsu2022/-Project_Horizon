package crawler

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

var hrefRegex = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)

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
			if !visited[key] {
				queue = append(queue, crawlNode{url: abs, depth: node.depth + 1})
			}
		}
	}

	return results
}

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

	matches := hrefRegex.FindAllStringSubmatch(string(body), -1)
	links := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" || strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "mailto:") {
			continue
		}
		links = append(links, v)
	}
	return links
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

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	q := u.Query()
	for k := range q {
		if strings.Contains(strings.ToLower(k), "session") || strings.Contains(strings.ToLower(k), "token") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return strings.TrimRight(u.String(), "/")
}
