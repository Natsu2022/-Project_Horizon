package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func NewClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
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

func EnsureURLScheme(rawURL string) string {
	if len(rawURL) >= 7 && (rawURL[:7] == "http://" || (len(rawURL) >= 8 && rawURL[:8] == "https://")) {
		return rawURL
	}
	return fmt.Sprintf("https://%s", rawURL)
}
