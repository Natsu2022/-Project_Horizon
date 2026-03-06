import requests
from .base_scanner import BaseScanner


class Scanner(BaseScanner):

    def scan(self):
        url = self.context["target"]

        findings = []

        try:
            r = requests.get(url, timeout=5)

            headers = r.headers

            if "X-Frame-Options" not in headers:
                findings.append({
                    "name": "Missing X-Frame-Options",
                    "severity": "Medium",
                    "description": "Clickjacking protection missing",
                    "recommendation": "Add X-Frame-Options header"
                })

            if "Content-Security-Policy" not in headers:
                findings.append({
                    "name": "Missing CSP",
                    "severity": "Medium",
                    "description": "Content Security Policy not set",
                    "recommendation": "Define CSP to mitigate XSS"
                })

        except:
            pass

        return findings