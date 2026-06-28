"""
core/header_analyser.py
Email header analysis — SPF, DKIM, DMARC, routing anomalies, display-name spoofing.
Max score contribution: 35 points.
"""

import re
from utils.logger import get_logger

logger = get_logger(__name__)

# Regex patterns
_RECEIVED_IP_RE  = re.compile(r"from\s+\S+\s+\[(\d{1,3}(?:\.\d{1,3}){3})\]", re.I)
_DISPLAY_NAME_RE = re.compile(r'"?([^"<]+)"?\s*<([^>]+)>', re.I)
_FREE_DOMAINS    = {"gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com",
                    "zoho.com","aol.com","icloud.com","mail.com","gmx.com","yandex.com",
                    "tutanota.com","guerrillamail.com","tempmail.com","mailinator.com"}
_SUSPICIOUS_TLD  = {".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".link",
                    ".online",".site",".info",".biz",".loan",".work",".stream"}


class HeaderAnalyser:

    def analyse(self, headers: dict, raw: str) -> dict:
        score    = 0
        findings = []
        flags    = {}

        # ── 1. SPF ───────────────────────────────────────────────
        auth = _hget(headers, "Authentication-Results") or ""
        received_spf = _hget(headers, "Received-SPF") or ""
        combined = (auth + " " + received_spf).lower()

        spf_fail = "spf=fail" in combined or "spf=softfail" in combined
        spf_none = "spf=none" in combined
        spf_pass = "spf=pass" in combined

        if spf_fail:
            score += 15
            findings.append({"type": "SPF FAIL", "severity": "high",
                              "detail": "SPF check failed — sender IP not authorised to send for this domain."})
            flags["spf_fail"] = True
        elif spf_none:
            score += 8
            findings.append({"type": "SPF NONE", "severity": "medium",
                              "detail": "No SPF record found for sender domain."})
        elif spf_pass:
            findings.append({"type": "SPF PASS", "severity": "clean",
                              "detail": "SPF validation passed."})

        # ── 2. DKIM ──────────────────────────────────────────────
        dkim_fail = "dkim=fail" in combined or "dkim=none" in combined
        dkim_pass = "dkim=pass" in combined

        if dkim_fail:
            score += 10
            findings.append({"type": "DKIM FAIL", "severity": "high",
                              "detail": "DKIM signature missing or invalid — email may have been tampered with."})
            flags["dkim_fail"] = True
        elif dkim_pass:
            findings.append({"type": "DKIM PASS", "severity": "clean",
                              "detail": "DKIM signature verified."})

        # ── 3. DMARC ─────────────────────────────────────────────
        dmarc_fail = "dmarc=fail" in combined
        dmarc_pass = "dmarc=pass" in combined

        if dmarc_fail:
            score += 10
            findings.append({"type": "DMARC FAIL", "severity": "high",
                              "detail": "DMARC policy not satisfied — high confidence of domain spoofing."})
            flags["dmarc_fail"] = True
        elif dmarc_pass:
            findings.append({"type": "DMARC PASS", "severity": "clean",
                              "detail": "DMARC policy satisfied."})

        # ── 4. From / Reply-To mismatch ──────────────────────────
        from_hdr      = _hget(headers, "From") or ""
        reply_to_hdr  = _hget(headers, "Reply-To") or ""
        from_domain   = _extract_domain(from_hdr)
        reply_domain  = _extract_domain(reply_to_hdr)

        if reply_domain and from_domain and reply_domain != from_domain:
            score += 8
            findings.append({"type": "REPLY-TO MISMATCH", "severity": "high",
                              "detail": f"From domain ({from_domain}) ≠ Reply-To domain ({reply_domain}) — classic BEC technique."})

        # ── 5. Display-name spoofing ─────────────────────────────
        m = _DISPLAY_NAME_RE.match(from_hdr.strip())
        if m:
            display_name = m.group(1).strip().lower()
            actual_email = m.group(2).strip().lower()
            legit_names  = ["amazon","paypal","microsoft","apple","google","bank","fedex","ups","dhl","irs","support"]
            for name in legit_names:
                if name in display_name and name not in actual_email:
                    score += 10
                    findings.append({"type": "DISPLAY-NAME SPOOF", "severity": "high",
                                     "detail": f"Display name contains '{name}' but email address does not. Classic spoofing."})
                    flags["display_name_spoof"] = True
                    break

        # ── 6. Free / throwaway sender domain ────────────────────
        if from_domain and from_domain.lower() in _FREE_DOMAINS:
            score += 5
            findings.append({"type": "FREE EMAIL SENDER", "severity": "medium",
                              "detail": f"Sender uses free email provider ({from_domain}). Unusual for corporate communications."})

        # ── 7. Suspicious TLD ────────────────────────────────────
        for tld in _SUSPICIOUS_TLD:
            if from_domain and from_domain.endswith(tld):
                score += 6
                findings.append({"type": "SUSPICIOUS SENDER TLD", "severity": "medium",
                                  "detail": f"Sender domain uses high-risk TLD: {tld}"})
                break

        # ── 8. Received header hop anomalies ─────────────────────
        received_hdrs = [v for k, v in headers.items() if k.lower() == "received"]
        if len(received_hdrs) > 6:
            score += 4
            findings.append({"type": "EXCESSIVE HOPS", "severity": "low",
                              "detail": f"{len(received_hdrs)} Received headers — unusually high relay count."})

        # ── 9. X-Mailer / User-Agent anomalies ───────────────────
        mailer = (_hget(headers, "X-Mailer") or _hget(headers, "User-Agent") or "").lower()
        bulk_keywords = ["bulk","mass","blast","phpmailer","sendgrid","mailchimp","sendinblue","mailjet","smtp2go"]
        for kw in bulk_keywords:
            if kw in mailer:
                score += 3
                findings.append({"type": "BULK MAILER DETECTED", "severity": "low",
                                  "detail": f"X-Mailer header indicates bulk sending tool: {mailer[:60]}"})
                break

        return {
            "score"    : min(35, score),
            "max_score": 35,
            "findings" : findings,
            **flags
        }


# ── Helpers ───────────────────────────────────────────────────────────
def _hget(headers: dict, key: str) -> str:
    """Case-insensitive header lookup."""
    for k, v in headers.items():
        if k.lower() == key.lower():
            return str(v)
    return ""

def _extract_domain(addr: str) -> str:
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""
