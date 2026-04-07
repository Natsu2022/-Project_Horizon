"""
api_client.py — VA Scanner Backend API Client
═══════════════════════════════════════════════
Thin wrapper around the Go backend REST API (http://127.0.0.1:5500).

Receives: user inputs collected by ScannerGUI (main.py)
Does:     builds the JSON payload, POSTs to /scan via a requests.Session
Returns:  parsed JSON dict (model.ScanResponse) back to ScannerGUI

Functions:
  _build_payload()           — assemble the ScanRequest JSON dict from GUI inputs
  start_scan_with_session()  — POST /scan using a caller-provided Session
                               (session.close() is used by GUI to cancel the scan)
  start_scan()               — convenience wrapper that creates its own Session
  health_check()             — GET /health → {"status":"ok"} for readiness polling

Data flow:
  GUI (main.py) ScanWorker.run()
      → start_scan_with_session(session, **payload)
          → POST http://127.0.0.1:5500/scan  (JSON body = ScanRequest)
          ← JSON response = ScanResponse
      → ScanWorker.finished.emit(result)
  GUI receives result dict and renders findings + report buttons.
"""

import requests

BASE_URL = "http://127.0.0.1:5500"


def _build_payload(target, options, report_formats, max_pages, max_depth, request_delay_ms,
                   zap_base_url="http://localhost:8880", zap_api_key="",
                   timed_mode=False, time_limit_secs=0, full_scan_mode=False,
                   auth=None, brute_force=None):
    """Build the ScanRequest JSON payload dict from individual GUI input values."""
    return {
        "target": target,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "request_delay_ms": request_delay_ms,
        "options": options or {
            "headers": True,
            "misconfig": True,
            "tls": True,
            "xss": True,
            "sqli": True,
            "cve": True,
            "zap": False,
            "bac": True,
        },
        "report_formats": report_formats or ["json", "html", "pdf"],
        "zap_base_url": zap_base_url,
        "zap_api_key": zap_api_key,
        "timed_mode": timed_mode,
        "time_limit_secs": time_limit_secs,
        "full_scan_mode": full_scan_mode,
        "auth": auth or {"enabled": False, "login_url": "", "username_field": "",
                         "password_field": "", "username": "", "password": ""},
        "brute_force": brute_force or {
            "enabled": False, "login_url": "", "username_field": "", "password_field": "",
            "usernames": [], "passwords": [], "delay_ms": 300,
            "stop_on_success": True, "max_attempts": 100,
        },
    }


def start_scan_with_session(session, target, options=None, report_formats=None, max_pages=30, max_depth=2,
                            request_delay_ms=100, zap_base_url="http://localhost:8880", zap_api_key="",
                            timed_mode=False, time_limit_secs=0, full_scan_mode=False,
                            auth=None, brute_force=None):
    """
    POST /scan using the provided requests.Session.

    The GUI passes its own Session so it can call session.close() to cancel
    a running scan (closes the underlying TCP connection → backend context is
    cancelled → engine stops crawling/scanning mid-flight).

    timeout=None is intentional — scans can take many minutes.
    Raises requests.HTTPError on non-2xx responses.
    """
    payload = _build_payload(target, options, report_formats, max_pages, max_depth, request_delay_ms,
                             zap_base_url, zap_api_key, timed_mode, time_limit_secs, full_scan_mode,
                             auth, brute_force)
    r = session.post(f"{BASE_URL}/scan", json=payload, timeout=None)
    r.raise_for_status()
    return r.json()


def start_scan(target, options=None, report_formats=None, max_pages=30, max_depth=2,
               request_delay_ms=100, zap_base_url="http://localhost:8880", zap_api_key="",
               timed_mode=False, time_limit_secs=0, full_scan_mode=False):
    session = requests.Session()
    return start_scan_with_session(session, target, options, report_formats, max_pages, max_depth,
                                   request_delay_ms, zap_base_url, zap_api_key, timed_mode, time_limit_secs,
                                   full_scan_mode)


def progress_check():
    """GET /progress → {"phase":..., "done":..., "total":..., "percent":...}"""
    r = requests.get(f"{BASE_URL}/progress", timeout=2)
    r.raise_for_status()
    return r.json()


def health_check():
    """
    GET /health → {"status": "ok"}

    Used by start.sh (and optionally the GUI) to wait until the Go backend
    is ready to accept scan requests. Raises on connection error or non-2xx.
    """
    r = requests.get(f"{BASE_URL}/health", timeout=2)
    r.raise_for_status()
    return r.json()


def cancel_scan():
    """
    POST /cancel — signals the Go backend to abort the current scan immediately.

    This is more reliable than closing the requests.Session because session.close()
    only prevents new connections; it does not interrupt a POST /scan that is
    already blocking while waiting for the response.
    """
    try:
        requests.post(f"{BASE_URL}/cancel", timeout=2)
    except Exception:
        pass


def logs_check(after=0):
    """
    GET /logs?after=N → {"lines": [...], "next": N}

    Returns backend log lines (from [Engine] and [ZAPScanner]) added since
    index `after`. The caller should pass the returned `next` value on the
    next call to receive only new lines (incremental polling).
    """
    r = requests.get(f"{BASE_URL}/logs", params={"after": after}, timeout=2)
    r.raise_for_status()
    return r.json()
