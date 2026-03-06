from .plugin_manager import load_scanners


class ScannerEngine:

    def __init__(self, target_url):
        self.context = {
            "target": target_url
        }

    def run(self):
        findings = []

        scanners = load_scanners(self.context)

        for scanner in scanners:
            try:
                results = scanner.scan()
                findings.extend(results)
            except Exception as e:
                print(f"Scanner error: {e}")

        return findings