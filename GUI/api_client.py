import requests

BASE_URL = "http://127.0.0.1:5500"


def _build_payload(target, options, report_formats, max_pages, max_depth, request_delay_ms,
                   zap_base_url="http://localhost:8880", zap_api_key=""):
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
        },
        "report_formats": report_formats or ["json", "html", "pdf"],
        "zap_base_url": zap_base_url,
        "zap_api_key": zap_api_key,
    }


def start_scan_with_session(session, target, options=None, report_formats=None, max_pages=30, max_depth=2,
                            request_delay_ms=100, zap_base_url="http://localhost:8880", zap_api_key=""):
    payload = _build_payload(target, options, report_formats, max_pages, max_depth, request_delay_ms,
                             zap_base_url, zap_api_key)
    r = session.post(f"{BASE_URL}/scan", json=payload, timeout=None)
    r.raise_for_status()
    return r.json()


def start_scan(target, options=None, report_formats=None, max_pages=30, max_depth=2,
               request_delay_ms=100, zap_base_url="http://localhost:8880", zap_api_key=""):
    session = requests.Session()
    return start_scan_with_session(session, target, options, report_formats, max_pages, max_depth,
                                   request_delay_ms, zap_base_url, zap_api_key)


def health_check():
    r = requests.get(f"{BASE_URL}/health", timeout=2)
    r.raise_for_status()
    return r.json()
