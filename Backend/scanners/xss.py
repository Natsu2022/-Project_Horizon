import requests
from .base_scanner import BaseScanner


class Scanner(BaseScanner):

    def scan(self):
        url = self.context["target"]

        payload = "<script>alert(1)</script>"
        test_url = f"{url}?q={payload}"

        try:
            r = requests.get(test_url, timeout=5)

            if payload in r.text:
                return [{
                    "name": "Reflected XSS",
                    "severity": "High",
                    "description": "User input reflected without sanitization",
                    "recommendation": "Implement output encoding and validation"
                }]
        except:
            pass

        return []