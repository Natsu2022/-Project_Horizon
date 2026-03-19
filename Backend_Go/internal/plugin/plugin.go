package plugin

// ─── Plugin Interface ─────────────────────────────────────────────────────────
//
// ScannerPlugin is the contract every scanner module must implement.
// The engine iterates over all enabled plugins for each crawled URL:
//
//   for each URLInfo:
//     for each plugin in engine.Plugins:
//       findings = append(findings, plugin.Scan(ctx, url)...)
//
// Current implementations:
//   HeaderScanner   — missing/weak HTTP security headers (A02/A06)
//   MisconfigScanner— dangerous HTTP methods via OPTIONS (A02)
//   TLSScanner      — TLS version and certificate issues (A04)
//   XSSScanner      — reflected XSS via nonce probe (A05)
//   SQLiScanner     — 3-phase SQL injection detection (A05)
//   CVEScanner      — outdated software banner matching (A03)
//   BACScanner      — broken access control checks (A01)
//   ZAPScanner      — OWASP ZAP spider + active scan integration (A01–A05)
//
// ─────────────────────────────────────────────────────────────────────────────

import "context"

import "vuln_assessment_app/internal/model"

// ScannerPlugin is the interface all scanner plugins must satisfy.
// Name returns the plugin's short identifier (used in Finding.Module and logs).
// Scan performs security checks on a single URL and returns any findings.
// ctx should be checked for cancellation during long-running operations.
type ScannerPlugin interface {
	Name() string
	Scan(ctx context.Context, url model.URLInfo) []model.Finding
}
