# VA Scanner Starter (Go Backend + PyQt GUI)

Starter project for a thesis-level vulnerability assessment tool.

## Features
- Domain-limited crawler (`max_pages`, `max_depth`)
- Pluggable scanner modules:
  - Headers
  - Security Misconfiguration
  - TLS checks
  - Basic reflected input check (XSS indicator)
  - Basic SQL error indicator (SQLi)
  - CVE/banner fingerprint (basic)
- Risk fields per finding (`severity`, `cvss_score`, `owasp_category`)
- Reports export to `JSON`, `HTML`, `PDF`

## OWASP Top 10:2025 Mapping
- Headers + Misconfig module -> `A02:2025-Security Misconfiguration`
- XSS + SQLi module -> `A05:2025-Injection`
- TLS module -> `A04:2025-Cryptographic Failures` (and cert lifecycle checks under `A02`)
- CVE/banner module -> `A03:2025-Software Supply Chain Failures`

The API response includes `owasp: \"OWASP Top 10:2025\"` and reports include the same standard marker.

## Run backend
```bash
cd Backend_Go
go run ./cmd/scanner
```

Server starts at `http://127.0.0.1:5500`

Health check:
```bash
curl http://127.0.0.1:5500/health
```

## Run GUI
```bash
cd GUI
python3 main.py
```

## API example
```bash
curl -X POST http://127.0.0.1:5500/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://example.com",
    "max_pages":20,
    "max_depth":2,
    "options":{"headers":true,"misconfig":true,"tls":true,"xss":true,"sqli":true,"cve":true},
    "report_formats":["json","html","pdf"]
  }'
```

Reports will be generated under `Backend_Go/reports/<scan_id>/`.

## Notes
This starter focuses on safe, basic detection logic suitable for thesis demos. It is not an exploitation framework.
