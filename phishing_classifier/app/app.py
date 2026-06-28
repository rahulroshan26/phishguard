"""
app/app.py — Flask web GUI for PhishGuard
Run: python app/app.py
"""

import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from core.classifier import PhishingClassifier
from utils.logger import get_logger

logger = get_logger(__name__)
app    = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "phishguard-dev-key-change-in-prod")

VT_API_KEY      = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_KEY", "")

classifier = PhishingClassifier(vt_api_key=VT_API_KEY, abuseipdb_key=ABUSEIPDB_KEY)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    raw_email = request.form.get("email_content", "").strip()
    if not raw_email:
        return render_template("index.html", error="Please paste an email to analyse.")

    try:
        result = classifier.classify(raw_email)
        return render_template("result.html", result=result)
    except Exception as exc:
        logger.error("Classification error: %s", exc, exc_info=True)
        return render_template("index.html",
                               error=f"Analysis failed: {exc}. Check logs for details.")


@app.route("/api/analyse", methods=["POST"])
def api_analyse():
    """REST API endpoint — accepts JSON or form data."""
    if request.is_json:
        data      = request.get_json()
        raw_email = data.get("email", "")
    else:
        raw_email = request.form.get("email", "")

    if not raw_email:
        return jsonify({"error": "No email content provided."}), 400

    try:
        result = classifier.classify(raw_email)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "vt_configured": bool(VT_API_KEY)})


@app.route("/samples")
def samples():
    """Load demo sample emails for quick testing."""
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "data", "samples")
    samples     = []
    if os.path.isdir(samples_dir):
        for f in sorted(os.listdir(samples_dir)):
            if f.endswith(".eml") or f.endswith(".txt"):
                path = os.path.join(samples_dir, f)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    samples.append({"name": f, "content": fh.read()})
    return render_template("samples.html", samples=samples)


if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    logger.info("PhishGuard starting on http://0.0.0.0:%d", port)
    app.run(host="0.0.0.0", port=port, debug=debug)
