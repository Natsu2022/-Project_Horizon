package standards

// ─── OWASP Top 10:2025 — Constants ───────────────────────────────────────────
//
// This package provides string constants for OWASP Top 10:2025 category names
// and their official reference URLs.
//
// Every Finding produced by a plugin must reference one of the A0X categories
// in OWASPCategory and link to the corresponding A0XURL for the report.
//
// Plugin → OWASP category mapping:
//   headers   → A06InsecureDesign (X-Frame-Options), A06 (all other headers)
//   misconfig → A02SecurityMisconfiguration
//   tls       → A04CryptographicFailures (weak TLS), A07AuthFailures (cert)
//   xss       → A05Injection
//   sqli      → A05Injection
//   cve       → A03SupplyChainFailures
//   bac       → A01BrokenAccessControl
//   zap       → varies by alert type (keyword-matched in zap_scanner.go)
//
// Reference: https://owasp.org/Top10/2025/
// ─────────────────────────────────────────────────────────────────────────────

const (
	OWASPTop10Version = "OWASP Top 10:2025"
)

const (
	A01BrokenAccessControl      = "A01:2025-Broken Access Control"
	A02SecurityMisconfiguration = "A02:2025-Security Misconfiguration"
	A03SupplyChainFailures      = "A03:2025-Software Supply Chain Failures"
	A04CryptographicFailures    = "A04:2025-Cryptographic Failures"
	A05Injection                = "A05:2025-Injection"
	A06InsecureDesign           = "A06:2025-Insecure Design"
	A07AuthFailures             = "A07:2025-Authentication Failures"
	A08SoftwareDataIntegrity    = "A08:2025-Software or Data Integrity Failures"
	A09LoggingAlerting          = "A09:2025-Logging and Alerting Failures"
	A10ExceptionalConditions    = "A10:2025-Mishandling of Exceptional Conditions"
)

const (
	Top2025OverviewURL = "https://owasp.org/Top10/2025/"
	A01URL             = "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/"
	A02URL             = "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/"
	A03URL             = "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"
	A04URL             = "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"
	A05URL             = "https://owasp.org/Top10/2025/A05_2025-Injection/"
	A06URL             = "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/"
	A07URL             = "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/"
	A08URL             = "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/"
	A09URL             = "https://owasp.org/Top10/2025/A09_2025-Logging_and_Alerting_Failures/"
	A10URL             = "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"
)

const (
	XSSCommunityURL  = "https://owasp.org/www-community/attacks/xss/"
	SQLiCommunityURL = "https://owasp.org/www-community/attacks/SQL_Injection"
)
