"""
PhishGuard - Email Phishing Classifier
core/classifier.py

Main classification engine. Analyses email headers, body, and URLs
to produce a phishing risk score and detailed evidence report.

Author  : Rahul Roshan
Project : PhishGuard — SOC Phishing Triage Tool
Version : 1.0.0
"""

import re
import email
import hashlib
import ipaddress
import socket
from datetime import datetime
from typing import Optional
from email import policy as email_policy

from core.header_analyser import HeaderAnalyser
from core.url_analyser    import URLAnalyser
from core.body_analyser   import BodyAnalyser
from utils.ioc_extractor  import IOCExtractor
from utils.logger         import get_logger

logger = get_logger(__name__)


class PhishingClassifier:
    """
    Multi-layer email phishing classifier.

    Scoring breakdown (total max = 100):
        Header analysis   : 35 points
        URL reputation    : 40 points
        Body analysis     : 25 points

    Verdict thresholds:
        >= 75  : MALICIOUS  (block & quarantine)
        50–74  : SUSPICIOUS (analyst review)
        25–49  : LOW RISK   (monitor)
        < 25   : CLEAN      (pass through)
    """

    VERDICT_MAP = [
        (75, "MALICIOUS",  "danger",  "🔴", "Block and quarantine immediately."),
        (50, "SUSPICIOUS", "warning", "🟡", "Escalate to Tier-2 analyst for review."),
        (25, "LOW RISK",   "info",    "🔵", "Monitor — no immediate action required."),
        (0,  "CLEAN",      "success", "🟢", "Email appears legitimate. Pass through."),
    ]

    def __init__(self, vt_api_key: str = "", abuseipdb_key: str = ""):
        self.header_analyser = HeaderAnalyser()
        self.url_analyser    = URLAnalyser(vt_api_key=vt_api_key)
        self.body_analyser   = BodyAnalyser()
        self.ioc_extractor   = IOCExtractor()
        self.vt_api_key      = vt_api_key
        self.abuseipdb_key   = abuseipdb_key

    # ──────────────────────────────────────────────────────────────
    def classify(self, raw_email: str) -> dict:
        """
        Main entry point. Accepts raw email (RFC 5322) or plain text.
        Returns a comprehensive result dict.
        """
        logger.info("Starting classification of email (%d bytes)", len(raw_email))

        # ── Parse email ──────────────────────────────────────────
        try:
            msg = email.message_from_string(raw_email, policy=email_policy.default)
        except Exception as exc:
            logger.warning("Email parse failed: %s — falling back to plain-text mode", exc)
            msg = None

        body_text  = self._extract_body(msg, raw_email)
        headers    = dict(msg.items()) if msg else {}

        # ── Run sub-analysers ────────────────────────────────────
        header_result = self.header_analyser.analyse(headers, raw_email)
        body_result   = self.body_analyser.analyse(body_text)
        iocs          = self.ioc_extractor.extract(body_text, headers)
        url_result    = self.url_analyser.analyse(iocs.get("urls", []))

        # ── Aggregate score ──────────────────────────────────────
        total_score = min(100, (
            header_result["score"] +
            url_result["score"]    +
            body_result["score"]
        ))

        verdict_label, verdict_class, verdict_icon, verdict_action = self._get_verdict(total_score)

        # ── Compose SHA-256 fingerprint ──────────────────────────
        fingerprint = hashlib.sha256(raw_email.encode()).hexdigest()

        result = {
            "timestamp"      : datetime.utcnow().isoformat() + "Z",
            "fingerprint"    : fingerprint,
            "total_score"    : total_score,
            "verdict"        : verdict_label,
            "verdict_class"  : verdict_class,
            "verdict_icon"   : verdict_icon,
            "verdict_action" : verdict_action,
            "breakdown" : {
                "header" : header_result,
                "url"    : url_result,
                "body"   : body_result,
            },
            "iocs"           : iocs,
            "email_meta"     : self._extract_meta(headers),
            "recommendations": self._build_recommendations(total_score, header_result, url_result, body_result),
        }

        logger.info("Classification complete — score=%d verdict=%s", total_score, verdict_label)
        return result

    # ──────────────────────────────────────────────────────────────
    def _get_verdict(self, score: int):
        for threshold, label, css_class, icon, action in self.VERDICT_MAP:
            if score >= threshold:
                return label, css_class, icon, action
        return "CLEAN", "success", "🟢", "Email appears legitimate."

    def _extract_body(self, msg, raw: str) -> str:
        if msg is None:
            return raw
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        parts.append(str(part.get_payload(decode=True) or ""))
        else:
            try:
                parts.append(msg.get_content())
            except Exception:
                parts.append(str(msg.get_payload(decode=True) or ""))
        return "\n".join(parts) or raw

    def _extract_meta(self, headers: dict) -> dict:
        return {
            "from"    : headers.get("From", headers.get("from", "Unknown")),
            "to"      : headers.get("To",   headers.get("to",   "Unknown")),
            "subject" : headers.get("Subject", headers.get("subject", "(no subject)")),
            "date"    : headers.get("Date",    headers.get("date",    "Unknown")),
            "msg_id"  : headers.get("Message-ID", "N/A"),
        }

    def _build_recommendations(self, score, header_r, url_r, body_r) -> list:
        recs = []
        if score >= 75:
            recs += [
                "🔴 Quarantine email immediately and block sender domain.",
                "🔴 Extract all IOCs and push to SIEM blocklist.",
                "🔴 Notify affected recipients and reset credentials if clicked.",
                "🔴 Submit samples to VirusTotal and your EDR sandbox.",
            ]
        elif score >= 50:
            recs += [
                "🟡 Escalate to Tier-2 analyst — do not release without review.",
                "🟡 Enrich extracted URLs and IPs against your TI feeds.",
                "🟡 Check for similar emails in the last 72 hours via SIEM.",
            ]
        else:
            recs.append("🟢 No immediate action required. Continue monitoring.")

        if header_r.get("spf_fail"):
            recs.append("📌 SPF check failed — sender domain may be spoofed.")
        if header_r.get("dkim_fail"):
            recs.append("📌 DKIM signature missing or invalid.")
        if header_r.get("dmarc_fail"):
            recs.append("📌 DMARC policy not satisfied — high spoofing confidence.")
        if url_r.get("malicious_count", 0) > 0:
            recs.append(f"📌 {url_r['malicious_count']} malicious URL(s) detected — block at proxy/firewall.")
        if body_r.get("credential_lure"):
            recs.append("📌 Credential harvesting language detected — warn users immediately.")
        return recs
