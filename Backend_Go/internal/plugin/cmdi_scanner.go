package plugin

// ─── CMDiScanner — OS Command Injection Detection (A05:2025) ─────────────────
//
// Receives: URLInfo — only processes URLs that have query parameters.
//           URLs without query params are skipped immediately (return nil).
// Does:     2-phase OS command injection detection per query parameter.
// Returns:  []Finding  (max one per parameter; stops at the first confirmed phase)
//
// Phase 1 — Time-Based  (primary signal, most reliable)
//   Payloads: shell sleep/ping commands injected into each query parameter value.
//   Detection: response time ≥ baseline + 4000 ms (min threshold 4500 ms).
//   Payloads chosen to produce measurable time delay without file I/O or
//   outbound network connections outside the target:
//     "; sleep 5 #"           Unix shell semicolon
//     "& sleep 5 &"           Windows cmd ampersand
//     "| sleep 5"             pipe subshell
//     "`sleep 5`"             backtick subshell
//     "$(sleep 5)"            dollar subshell
//     "; ping -c 5 127.0.0.1" Unix ping loop (alternative time source)
//     "& ping -n 5 127.0.0.1 &" Windows ping loop
//
// Phase 2 — Output-Based  (secondary signal, confirms execution)
//   Uses the same timed request but checks the response body for patterns
//   characteristic of command output (uid=, /etc/passwd, dir listings, etc.).
//   Only runs when Phase 1 did not trigger (avoids redundant requests).
//
// OWASP: A05:2025 Injection | CWE-78
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

// cmdiOutputRegex matches command output patterns that indicate successful execution.
var cmdiOutputRegex = regexp.MustCompile(
	`(?i)(` +
		`uid=\d+|` +
		`gid=\d+|` +
		`root:x:|` +
		`/etc/passwd|` +
		`/etc/shadow|` +
		`Directory of [A-Z]:\\|` +
		`Volume in drive [A-Z]|` +
		`Windows IP Configuration|` +
		`bytes from 127\.0\.0\.1` +
		`)`,
)

// cmdiTimePayloads inject time-delay commands using various shell syntax forms.
// sleep/ping chosen to be observable by timing only — no file writes or external calls.
var cmdiTimePayloads = []string{
	"; sleep 5 #",            // Unix semicolon, hash comment
	"& sleep 5 &",            // Windows cmd ampersand chain
	"| sleep 5",              // Unix pipe
	"`sleep 5`",              // backtick subshell
	"$(sleep 5)",             // dollar subshell
	"; ping -c 5 127.0.0.1", // Unix ping loopback (5 × ~1 s = ~5 s)
	"& ping -n 5 127.0.0.1 &", // Windows ping loopback
}

// CMDiScanner implements the ScannerPlugin interface for OS command injection.
type CMDiScanner struct {
	// FullScan disables the early-exit optimisation so both detection phases
	// always run for every parameter, collecting all evidence types.
	FullScan bool
}

func (c *CMDiScanner) Name() string {
	return "cmdi"
}

func (c *CMDiScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	parsed, err := url.Parse(u.URL)
	if err != nil {
		return nil
	}
	q := parsed.Query()
	if len(q) == 0 {
		return nil
	}

	findings := []model.Finding{}
	idx := 0

	for key := range q {
		if ctx.Err() != nil {
			return findings
		}

		// Phase 1: time-based detection
		if f := cmdiTimeBased(ctx, parsed, key, u.URL, idx); f != nil {
			findings = append(findings, *f)
			idx++
			if !c.FullScan {
				continue // confirmed for this param; skip output-based phase
			}
		}

		// Phase 2: output-based detection
		if f := cmdiOutputBased(ctx, parsed, key, u.URL, idx); f != nil {
			findings = append(findings, *f)
			idx++
		}
	}

	return findings
}

// cmdiTimeBased tests time-delay payloads for a single parameter.
func cmdiTimeBased(ctx context.Context, parsed *url.URL, key, baseURL string, idx int) *model.Finding {
	baseline, _, _ := fetchCMDiTimed(ctx, parsed.String())
	if baseline == 0 {
		return nil
	}
	threshold := baseline + 4000
	if threshold < 4500 {
		threshold = 4500
	}

	for _, payload := range cmdiTimePayloads {
		if ctx.Err() != nil {
			return nil
		}
		testURL := *parsed
		testQ := testURL.Query()
		testQ.Set(key, payload)
		testURL.RawQuery = testQ.Encode()

		elapsed, reqDump, respDump := fetchCMDiTimed(ctx, testURL.String())
		if elapsed >= threshold {
			f := model.NewFinding(
				"cmdi",
				"time_based_cmdi",
				"Potential OS Command Injection (Time-Based)",
				"The server response was delayed significantly after injecting a time-delay OS command payload into a query parameter, suggesting OS command injection.",
				"Critical",
				standards.A05Injection,
				testURL.String(),
				"Parameter '"+key+"': baseline="+cmdiItoa(int(baseline))+"ms, elapsed="+cmdiItoa(int(elapsed))+"ms with payload: "+payload,
				"Avoid passing user-supplied input to shell commands. Use safe APIs, whitelist input values, and run processes with least privilege.",
				standards.A05URL+" | https://owasp.org/www-community/attacks/Command_Injection",
			)
			f.ID = buildID("CMD", baseURL, idx)
			f.CWEIDs = []string{"CWE-78"}
			f.Request = reqDump
			f.Response = respDump
			return &f
		}
	}
	return nil
}

// cmdiOutputBased injects each payload and checks the response body for command output.
func cmdiOutputBased(ctx context.Context, parsed *url.URL, key, baseURL string, idx int) *model.Finding {
	for _, payload := range cmdiTimePayloads {
		if ctx.Err() != nil {
			return nil
		}
		testURL := *parsed
		testQ := testURL.Query()
		testQ.Set(key, payload)
		testURL.RawQuery = testQ.Encode()

		body, reqDump, respDump, err := fetchCMDiBody(ctx, testURL.String())
		if err != nil {
			continue
		}
		if cmdiOutputRegex.Match(body) {
			f := model.NewFinding(
				"cmdi",
				"output_based_cmdi",
				"Potential OS Command Injection (Output Reflected)",
				"Command output pattern was detected in the server response after injecting an OS command payload, suggesting OS command injection.",
				"Critical",
				standards.A05Injection,
				testURL.String(),
				"Parameter '"+key+"': command output pattern matched in response with payload: "+payload,
				"Avoid passing user-supplied input to shell commands. Use safe APIs, whitelist input values, and run processes with least privilege.",
				standards.A05URL+" | https://owasp.org/www-community/attacks/Command_Injection",
			)
			f.ID = buildID("CMD", baseURL, idx)
			f.CWEIDs = []string{"CWE-78"}
			f.Request = reqDump
			f.Response = respDump
			return &f
		}
	}
	return nil
}

// fetchCMDiTimed performs a GET with a 12-second timeout (accommodates sleep 5 + latency)
// and returns the response time in milliseconds, plus request/response dumps.
func fetchCMDiTimed(ctx context.Context, rawURL string) (int64, string, string) {
	client := &http.Client{Timeout: 12 * time.Second}
	req, err := httpclient.NewRequestCtx(ctx, rawURL)
	if err != nil {
		return 0, "", ""
	}
	start := time.Now()
	resp, reqDump, respDump, err := httpclient.DoCapture(client, req)
	if err != nil {
		return 0, reqDump, ""
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return time.Since(start).Milliseconds(), reqDump, respDump
}

// fetchCMDiBody performs a GET and returns the response body plus request/response dumps.
func fetchCMDiBody(ctx context.Context, rawURL string) ([]byte, string, string, error) {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, rawURL)
	if err != nil {
		return nil, "", "", err
	}
	resp, reqDump, respDump, err := httpclient.DoCapture(client, req)
	if err != nil {
		return nil, reqDump, "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	if err != nil {
		return nil, reqDump, respDump, err
	}
	return body, reqDump, respDump, nil
}

// cmdiItoa converts an int to a decimal string without importing strconv.
func cmdiItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 20)
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}