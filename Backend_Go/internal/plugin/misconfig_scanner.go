package plugin

import (
	"context"
	"strings"

	"vuln_assessment_app/internal/httpclient"
	"vuln_assessment_app/internal/model"
	"vuln_assessment_app/internal/standards"
)

type MisconfigScanner struct{}

func (m *MisconfigScanner) Name() string {
	return "misconfig"
}

func (m *MisconfigScanner) Scan(ctx context.Context, u model.URLInfo) []model.Finding {
	client := httpclient.NewClient()
	optionsReq, err := httpclient.NewMethodRequestCtx(ctx, "OPTIONS", u.URL)
	if err != nil {
		return nil
	}
	resp, err := client.Do(optionsReq)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allow := strings.ToUpper(resp.Header.Get("Allow"))
	if allow == "" {
		return nil
	}

	riskyMethods := []string{"TRACE", "PUT", "DELETE"}
	findings := []model.Finding{}
	for idx, method := range riskyMethods {
		if strings.Contains(allow, method) {
			f := model.NewFinding(
				"misconfig",
				"dangerous_http_method",
				"Potentially dangerous HTTP method enabled",
				"Server advertises HTTP methods that are often unnecessary on public-facing applications.",
				"Medium",
				standards.A02SecurityMisconfiguration,
				u.URL,
				"Allow header includes "+method,
				"Disable unused methods and enforce method-level access control.",
				standards.A02URL,
			)
			f.ID = buildID("MIS", u.URL, idx)
			findings = append(findings, f)
		}
	}

	return findings
}
