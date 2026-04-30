"""
web/app.py — Flask web UI for DSGVO Compliance Checker.

Run with: python3 web/app.py
Visit:    http://localhost:5000
"""

import json
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from checker.scanner import scan

app = Flask(__name__)

# In-memory scan history (resets on restart)
scan_history: list[dict] = []
MAX_HISTORY = 20


def result_to_dict(result) -> dict:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "scanned_at": result.scanned_at,
        "duration_seconds": result.duration_seconds,
        "score": result.score,
        "rating": result.rating,
        "error": result.error,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "severity": c.severity,
                "detail": c.detail,
                "recommendation": c.recommendation,
                "gdpr_reference": c.gdpr_reference,
                "found_items": c.found_items,
            }
            for c in result.checks
        ],
        "passed_count": len(result.passed),
        "failed_count": len(result.failed),
        "critical_count": len(result.critical_failures),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = scan(url)
    result_dict = result_to_dict(result)

    # Add to history
    scan_history.insert(0, result_dict)
    if len(scan_history) > MAX_HISTORY:
        scan_history.pop()

    return jsonify(result_dict)


@app.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json()
    url_a = (data or {}).get("url_a", "").strip()
    url_b = (data or {}).get("url_b", "").strip()

    if not url_a or not url_b:
        return jsonify({"error": "Both URLs are required"}), 400

    result_a = scan(url_a)
    result_b = scan(url_b)

    return jsonify({
        "a": result_to_dict(result_a),
        "b": result_to_dict(result_b),
    })


@app.route("/api/history")
def api_history():
    return jsonify(scan_history)


if __name__ == "__main__":
    print("\n  DSGVO Compliance Checker — Web UI")
    print("  Running at: http://localhost:5000\n")
    app.run(debug=True, port=5000)
