package httpclient

// ─── HTTP Client Factory ──────────────────────────────────────────────────────
//
// Provides shared http.Client instances and request constructors used by
// the crawler and all scanner plugins.
//
// Design choices:
//   - Timeout: 8 seconds on all clients (balance between thoroughness and speed).
//   - User-Agent: Chrome/120 on Linux — mimics a real browser so sites don't
//     block the scanner with a "bot detected" response.
//   - HTTP/2 disabled (ForceAttemptHTTP2: false) — keeps response headers
//     simpler and avoids h2-only quirks during header inspection.
//   - NewClientNoRedirect: stops at the first 3xx response so the BACScanner
//     can read the Location header directly (open redirect detection).
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"time"
)

// sessionJar is a shared cookie jar set once per scan by engine.SetSessionJar().
// nil means no session — each request is unauthenticated.
// Not concurrency-safe across simultaneous scans; this app runs one scan at a time.
var sessionJar http.CookieJar

// SetSessionJar sets the cookie jar used by all NewClient / NewClientNoRedirect calls.
// Call with a populated jar after login, and call SetSessionJar(nil) after the scan.
func SetSessionJar(jar http.CookieJar) { sessionJar = jar }

// NewCookieJar creates a new cookie jar for use with SetSessionJar.
func NewCookieJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func NewClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Jar:     sessionJar,
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
		},
	}
}

// NewClientNoRedirect returns an HTTP client that does not follow redirects.
// Used for open redirect detection so the 3xx Location header can be inspected.
func NewClientNoRedirect() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Jar:     sessionJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
		},
	}
}

func NewRequest(rawURL string) (*http.Request, error) {
	return NewRequestCtx(context.Background(), rawURL)
}

func NewRequestCtx(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	return req, nil
}

func NewMethodRequest(method, rawURL string) (*http.Request, error) {
	return NewMethodRequestCtx(context.Background(), method, rawURL)
}

func NewMethodRequestCtx(ctx context.Context, method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	return req, nil
}

// DoCapture executes req and returns (response, requestDump, responseHeadersDump, error).
// Only response headers are captured — the body is NOT consumed so callers
// can still read resp.Body normally with io.ReadAll / io.LimitReader.
func DoCapture(client *http.Client, req *http.Request) (*http.Response, string, string, error) {
	reqBytes, _ := httputil.DumpRequestOut(req, false)
	resp, err := client.Do(req)
	if err != nil {
		return nil, string(reqBytes), "", err
	}
	respBytes, _ := httputil.DumpResponse(resp, false) // false = headers only, body untouched
	return resp, string(reqBytes), string(respBytes), nil
}

// EnsureURLScheme prepends "https://" to rawURL if no scheme is present.
// Called by the crawler and ScanHandler to normalise user-supplied targets
// like "example.com" → "https://example.com".
func EnsureURLScheme(rawURL string) string {
	if len(rawURL) >= 7 && (rawURL[:7] == "http://" || (len(rawURL) >= 8 && rawURL[:8] == "https://")) {
		return rawURL
	}
	return fmt.Sprintf("https://%s", rawURL)
}
