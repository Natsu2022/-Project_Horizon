from flask import Flask, request, jsonify
from flask_cors import CORS

from core.scanner_engine import ScannerEngine
from services.validation_service import validate_url

app = Flask(__name__)
CORS(app)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("target")

    if not validate_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    engine = ScannerEngine(url)
    findings = engine.run()

    return jsonify({
        "target": url,
        "findings": findings
    })


if __name__ == "__main__":
    app.run(port=5000)