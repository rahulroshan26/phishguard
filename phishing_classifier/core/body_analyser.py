"""
core/body_analyser.py
Email body content analysis — urgency language, credential lures,
attachment indicators, HTML obfuscation.
Max score contribution: 25 points.
"""

import re
import html
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Pattern libraries ─────────────────────────────────────────────────
URGENCY_PATTERNS = [
    r"urgent(ly)?", r"immediate(ly)?", r"act now", r"action required",
    r"account (will be|has been) (suspended|disabled|limited|locked)",
    r"verify your (account|identity|email|information)",
    r"confirm your (account|identity|email|details)",
    r"within 24 hours?", r"within 48 hours?", r"expires? (today|soon|immediately)",
    r"unusual (sign-?in|activity|login|access)", r"security alert",
    r"your account (is|has been) (compromised|hacked|at risk)",
    r"click (here|below|the link) (to|and) (verify|confirm|update|secure)",
]

CREDENTIAL_PATTERNS = [
    r"enter your (password|username|email|credentials|login)",
    r"(update|reset|change) your password",
    r"(login|sign.?in) (to|with) your (account|credentials)",
    r"provide your (banking|credit card|social security|ssn|pin)",
    r"(bank|credit card|debit card) (details?|number|information)",
    r"one.?time.?password|OTP",
    r"two.?factor|2FA",
    r"security code",
]

FINANCIAL_PATTERNS = [
    r"(your|a) payment (of|for|is due)",
    r"(invoice|receipt|order) (attached|enclosed|#?\d+)",
    r"(wire transfer|bank transfer|ach|swift)",
    r"(refund|reimbursement) (of|for)",
    r"cryptocurrency|bitcoin|crypto wallet",
    r"gift card(s)?",
    r"western union|money gram",
]

OBFUSCATION_PATTERNS = [
    r"&amp;", r"&#x?[0-9a-f]+;", r"base64",
    r"<!--.*?-->",  # HTML comments
    r"display\s*:\s*none",
    r"font-size\s*:\s*0",
    r"color\s*:\s*white.*background.*white",
    r"visibility\s*:\s*hidden",
]

ATTACHMENT_KEYWORDS = [
    "invoice","payment","receipt","document","form","pdf","spreadsheet",
    "docx","xlsx","zip","rar","exe","js","vbs","bat","cmd","ps1","lnk",
]


class BodyAnalyser:

    def analyse(self, body: str) -> dict:
        body_lower = body.lower()
        clean_body = html.unescape(body_lower)

        score    = 0
        findings = []
        flags    = {}

        # ── 1. Urgency / pressure language ───────────────────────
        urgency_hits = self._match_patterns(clean_body, URGENCY_PATTERNS)
        if urgency_hits:
            s = min(8, len(urgency_hits) * 2)
            score += s
            findings.append({"type": "URGENCY LANGUAGE", "severity": "medium",
                              "detail": f"Psychological pressure language detected: {', '.join(urgency_hits[:3])}"})

        # ── 2. Credential harvesting lure ────────────────────────
        cred_hits = self._match_patterns(clean_body, CREDENTIAL_PATTERNS)
        if cred_hits:
            score += 8
            flags["credential_lure"] = True
            findings.append({"type": "CREDENTIAL LURE", "severity": "high",
                              "detail": f"Credential harvesting language: {', '.join(cred_hits[:2])}"})

        # ── 3. Financial / payment fraud ─────────────────────────
        fin_hits = self._match_patterns(clean_body, FINANCIAL_PATTERNS)
        if fin_hits:
            s = min(6, len(fin_hits) * 2)
            score += s
            findings.append({"type": "FINANCIAL LURE", "severity": "medium",
                              "detail": f"Financial fraud language detected: {', '.join(fin_hits[:2])}"})

        # ── 4. HTML obfuscation ───────────────────────────────────
        obf_hits = self._match_patterns(body, OBFUSCATION_PATTERNS)
        if obf_hits:
            score += 5
            findings.append({"type": "HTML OBFUSCATION", "severity": "high",
                              "detail": "Email body contains hidden/obfuscated HTML elements — common in phishing kits."})

        # ── 5. Suspicious attachment references ──────────────────
        att_hits = [kw for kw in ATTACHMENT_KEYWORDS if kw in clean_body]
        if att_hits:
            s = min(4, len(att_hits))
            score += s
            findings.append({"type": "ATTACHMENT REFERENCE", "severity": "low",
                              "detail": f"Body references file types/documents: {', '.join(att_hits[:5])}"})

        # ── 6. Generic greeting (Dear Customer, Dear User) ────────
        if re.search(r"dear (customer|user|client|member|account holder|valued)", clean_body):
            score += 2
            findings.append({"type": "GENERIC GREETING", "severity": "low",
                              "detail": "Generic salutation (e.g. 'Dear Customer') — personalised phishing uses actual names."})

        # ── 7. Excessive punctuation / ALL CAPS ──────────────────
        if len(re.findall(r"[!]{2,}", body)) >= 3 or len(re.findall(r"[A-Z]{5,}", body)) >= 5:
            score += 2
            findings.append({"type": "EXCESSIVE EMPHASIS", "severity": "low",
                              "detail": "Multiple exclamation marks or ALL-CAPS segments detected — common in spam."})

        # ── Word count sanity check ───────────────────────────────
        word_count = len(clean_body.split())
        if word_count < 20:
            score += 2
            findings.append({"type": "VERY SHORT BODY", "severity": "low",
                              "detail": f"Email body is very short ({word_count} words) — may be a lure to click a link."})

        return {
            "score"          : min(25, score),
            "max_score"      : 25,
            "findings"       : findings,
            "word_count"     : word_count,
            **flags,
        }

    def _match_patterns(self, text: str, patterns: list) -> list:
        hits = []
        for p in patterns:
            m = re.search(p, text, re.I)
            if m:
                hits.append(m.group(0)[:50])
        return hits
