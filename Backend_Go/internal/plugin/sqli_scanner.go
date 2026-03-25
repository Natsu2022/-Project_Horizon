package plugin

// ─── SQLiScanner — SQL Injection Detection (A05:2025) ────────────────────────
//
// Receives: URLInfo — only processes URLs that have query parameters.
//           URLs without query params are skipped immediately (return nil).
// Does:     3-phase SQL injection detection per query parameter.
// Returns:  []Finding  (max one per parameter; stops at the first confirmed phase)
//
// Phase 1 — Error-Based  (fastest, ~3 HTTP requests per param)
//   Payloads: ' | '' | ' OR ''='
//   Detection: response body matches SQL error strings (mysql_fetch, ORA-XXXX, etc.)
//   If triggered → report "error_based_sqli" and skip phases 2 & 3 for this param.
//
// Phase 2 — Boolean-Based Blind  (2×2 HTTP requests per param)
//   Payload pairs: true condition vs false condition
//     "1 AND 1=1--"  vs  "1 AND 1=2--"
//     "1 AND 'a'='a'--"  vs  "1 AND 'a'='b'--"
//   Detection: response body size differs by >10% (min 50 bytes) between T/F payloads.
//   If triggered → report "boolean_blind_sqli" and skip phase 3.
//
// Phase 3 — Time-Based Blind  (slowest, up to 4×10s per param)
//   Payloads: SLEEP(3) for MySQL, pg_sleep(3) for PostgreSQL, WAITFOR DELAY for MSSQL.
//   Detection: response time ≥ baseline + 2000 ms (min threshold 2500 ms).
//   Most expensive: each payload can take up to 10 seconds.
//
// OWASP: A05:2025 Injection | CWE-89
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

var sqliErrorRegex = regexp.MustCompile(
	`(?i)(` +
		`sql syntax|` +
		`mysql_fetch|` +
		`mysql_num_rows|` +
		`syntax error|` +
		`odbc|` +
		`sqlite|` +
		`psql|` +
		`postgresql|` +
		`unterminated quoted string|` +
		`ORA-[0-9]{4,}|` +
		`Microsoft OLE DB Provider|` +
		`Warning: pg_|` +
		`Warning: mysql_|` +
		`You have an error in your SQL|` +
		`Unclosed quotation mark|` +
		`quoted string not properly terminated` +
		`)`,
)

// sqliErrorPayloads trigger SQL syntax errors on vulnerable backends.
var sqliErrorPayloads = []string{"'", "''", `' OR ''='`}

type boolPair struct {
	truePayload  string // should return same result as original value
	falsePayload string // should return different result on a vulnerable backend
}

// sqliBoolPairs are used for boolean-based blind SQLi detection.
var sqliBoolPairs = []boolPair{
	{"1 AND 1=1--", "1 AND 1=2--"},
	{"1 AND 'a'='a'--", "1 AND 'a'='b'--"},
}

// sqliTimePayloads trigger server-side sleep on vulnerable backends.
var sqliTimePayloads = []string{
	"' OR SLEEP(3)--",           // MySQL
	"' OR SLEEP(3)#",            // MySQL (hash comment)
	"'; SELECT pg_sleep(3)--",   // PostgreSQL
	"'; WAITFOR DELAY '0:0:3'--", // MSSQL
}

type SQLiScanner struct {
	// FullScan disables the early-exit optimisation: all three detection phases
	// (error-based, boolean-blind, time-based) are always run for every parameter
	// regardless of whether an earlier phase already produced a finding.
	FullScan bool
}

func (s *SQLiScanner) Name() string {
	return "sqli"
}

func (s *SQLiScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
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

		// Phase 1: error-based detection
		if f := sqliErrorBased(ctx, parsed, key, u.URL, idx); f != nil {
			findings = append(findings, *f)
			idx++
			if !s.FullScan {
				continue // Normal/Timed mode: confirmed for this param; skip remaining phases
			}
			// Full Scan mode: continue to phases 2 & 3 to collect all evidence types
		}

		// Phase 2: boolean-based blind detection
		if f := sqliBooleanBased(ctx, parsed, key, u.URL, idx); f != nil {
			findings = append(findings, *f)
			idx++
			if !s.FullScan {
				continue // Normal/Timed mode: skip time-based phase
			}
		}

		// Phase 3: time-based blind detection
		if f := sqliTimeBased(ctx, parsed, key, u.URL, idx); f != nil {
			findings = append(findings, *f)
			idx++
		}
	}

	return findings
}

// sqliErrorBased tests error-triggering payloads for a single parameter.
func sqliErrorBased(ctx context.Context, parsed *url.URL, key, baseURL string, idx int) *model.Finding {
	for _, payload := range sqliErrorPayloads {
		if ctx.Err() != nil {
			return nil
		}
		testURL := *parsed
		testQ := testURL.Query()
		testQ.Set(key, payload)
		testURL.RawQuery = testQ.Encode()

		body, _, reqDump, respDump, err := fetchSQLiBody(ctx, testURL.String())
		if err != nil {
			continue
		}
		if sqliErrorRegex.MatchString(string(body)) {
			f := model.NewFinding(
				"sqli",
				"error_based_sqli",
				"Potential SQL Injection (Error-Based)",
				"Backend returned a SQL error message after injecting a quote character into a query parameter.",
				"High",
				standards.A05Injection,
				testURL.String(),
				"Parameter '"+key+"' triggered SQL error with payload: "+payload,
				"Use parameterized queries / prepared statements and enforce strict server-side input validation.",
				standards.A05URL+" | "+standards.SQLiCommunityURL,
			)
			f.ID = buildID("SQL", baseURL, idx)
			f.CWEIDs = []string{"CWE-89"}
			f.Request = reqDump
			f.Response = respDump
			return &f
		}
	}
	return nil
}

// sqliBooleanBased compares response sizes for true/false condition payloads.
func sqliBooleanBased(ctx context.Context, parsed *url.URL, key, baseURL string, idx int) *model.Finding {
	for _, pair := range sqliBoolPairs {
		if ctx.Err() != nil {
			return nil
		}

		trueURL := *parsed
		tq := trueURL.Query()
		tq.Set(key, pair.truePayload)
		trueURL.RawQuery = tq.Encode()

		falseURL := *parsed
		fq := falseURL.Query()
		fq.Set(key, pair.falsePayload)
		falseURL.RawQuery = fq.Encode()

		_, trueLen, reqDump, respDump, err := fetchSQLiBody(ctx, trueURL.String())
		if err != nil || trueLen == 0 {
			continue
		}
		_, falseLen, _, _, err := fetchSQLiBody(ctx, falseURL.String())
		if err != nil {
			continue
		}

		diff := trueLen - falseLen
		if diff < 0 {
			diff = -diff
		}
		threshold := trueLen / 10 // 10% of baseline
		if threshold < 50 {
			threshold = 50
		}

		if diff > threshold {
			f := model.NewFinding(
				"sqli",
				"boolean_blind_sqli",
				"Potential SQL Injection (Boolean-Based Blind)",
				"Response body size differed significantly between a true and false boolean condition, suggesting blind SQL injection.",
				"High",
				standards.A05Injection,
				trueURL.String(),
				"Parameter '"+key+"': true-response="+sqliItoa(trueLen)+"B, false-response="+sqliItoa(falseLen)+"B, delta="+sqliItoa(diff)+"B",
				"Use parameterized queries / prepared statements and enforce strict server-side input validation.",
				standards.A05URL+" | "+standards.SQLiCommunityURL,
			)
			f.ID = buildID("SQL", baseURL, idx)
			f.CWEIDs = []string{"CWE-89"}
			f.Request = reqDump
			f.Response = respDump
			return &f
		}
	}
	return nil
}

// fetchSQLiBody performs a GET and returns the response body, its length, and request/response dumps.
func fetchSQLiBody(ctx context.Context, rawURL string) ([]byte, int, string, string, error) {
	client := httpclient.NewClient()
	req, err := httpclient.NewRequestCtx(ctx, rawURL)
	if err != nil {
		return nil, 0, "", "", err
	}
	resp, reqDump, respDump, err := httpclient.DoCapture(client, req)
	if err != nil {
		return nil, 0, reqDump, "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	if err != nil {
		return nil, 0, reqDump, respDump, err
	}
	return body, len(body), reqDump, respDump, nil
}

// sqliTimeBased tests time-delay payloads for a single parameter.
func sqliTimeBased(ctx context.Context, parsed *url.URL, key, baseURL string, idx int) *model.Finding {
	baseline, _, _ := fetchSQLiTimed(ctx, parsed.String())
	if baseline == 0 {
		return nil
	}
	threshold := baseline + 2000
	if threshold < 2500 {
		threshold = 2500
	}

	for _, payload := range sqliTimePayloads {
		if ctx.Err() != nil {
			return nil
		}
		testURL := *parsed
		testQ := testURL.Query()
		testQ.Set(key, payload)
		testURL.RawQuery = testQ.Encode()

		elapsed, reqDump, respDump := fetchSQLiTimed(ctx, testURL.String())
		if elapsed >= threshold {
			f := model.NewFinding(
				"sqli",
				"time_based_sqli",
				"Potential SQL Injection (Time-Based Blind)",
				"Response was delayed significantly after injecting a time-delay payload, suggesting blind SQL injection.",
				"High",
				standards.A05Injection,
				testURL.String(),
				"Parameter '"+key+"': baseline="+sqliItoa(int(baseline))+"ms, elapsed="+sqliItoa(int(elapsed))+"ms with payload: "+payload,
				"Use parameterized queries / prepared statements and enforce strict server-side input validation.",
				standards.A05URL+" | "+standards.SQLiCommunityURL,
			)
			f.ID = buildID("SQL", baseURL, idx)
			f.CWEIDs = []string{"CWE-89"}
			f.Request = reqDump
			f.Response = respDump
			return &f
		}
	}
	return nil
}

// fetchSQLiTimed performs a GET and returns the response time in milliseconds plus request/response dumps.
func fetchSQLiTimed(ctx context.Context, rawURL string) (int64, string, string) {
	client := &http.Client{Timeout: 10 * time.Second}
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

// sqliItoa converts an int to a decimal string without importing strconv.
func sqliItoa(n int) string {
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
