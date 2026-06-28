"""
core/url_analyser.py
URL reputation scoring via VirusTotal API + heuristic checks.
Max score contribution: 40 points.
"""

import re
import time
import hashlib
import requests
from urllib.parse import urlparse
from utils.logger import get_logger

logger = get_logger(__name__)

_SUSPICIOUS_KEYWORDS = [
    "login","signin","verify","account","update","secure","banking","password",
    "credential","confirm","suspend","unusual","activity","recover","click","now",
    "urgent","reset","authenticate","validate","access","alert","notification",
    "docusign","dropbox","sharepoint","onedrive","office365","paypal","amazon","apple"
]
_SUSPICIOUS_TLD = {".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".link",
                   ".online",".site",".info",".loan",".work",".stream",".pw"}
_URL_SHORTENERS = {"bit.ly","tinyurl.com","ow.ly","t.co","goo.gl","short.io",
                   "rb.gy","cutt.ly","is.gd","buff.ly","tiny.cc","lnkd.in"}


class URLAnalyser:

    def __init__(self, vt_api_key: str = ""):
        self.vt_api_key = vt_api_key

    def analyse(self, urls: list) -> dict:
        if not urls:
            return {"score": 0, "max_score": 40, "findings": [],
                    "malicious_count": 0, "total_urls": 0, "url_details": []}

        score        = 0
        findings     = []
        url_details  = []
        malicious_ct = 0

        for url in urls[:15]:  # cap at 15 URLs per email
            url_score, url_findings, vt_data = self._score_url(url)
            score        += url_score
            findings     += url_findings
            malicious_ct += 1 if url_score >= 20 else 0
            url_details.append({
                "url"      : url[:120],
                "score"    : url_score,
                "findings" : url_findings,
                "vt"       : vt_data,
            })

        return {
            "score"          : min(40, score),
            "max_score"      : 40,
            "findings"       : findings,
            "malicious_count": malicious_ct,
            "total_urls"     : len(urls),
            "url_details"    : url_details,
        }

    # ──────────────────────────────────────────────────────────────
    def _score_url(self, url: str):
        score    = 0
        findings = []
        vt_data  = {}

        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower().replace("www.", "")
        path   = (parsed.path + "?" + parsed.query).lower()

        # ── 1. HTTP (no TLS) ─────────────────────────────────────
        if url.startswith("http://"):
            score += 5
            findings.append({"type": "NO TLS", "severity": "medium",
                              "detail": f"URL uses HTTP — no encryption: {url[:80]}"})

        # ── 2. IP address as host ─────────────────────────────────
        host = parsed.hostname or ""
        try:
            import ipaddress
            ipaddress.ip_address(host)
            score += 12
            findings.append({"type": "IP ADDRESS URL", "severity": "high",
                              "detail": f"URL uses raw IP address instead of domain: {host}"})
        except ValueError:
            pass

        # ── 3. URL shortener ──────────────────────────────────────
        if domain in _URL_SHORTENERS:
            score += 8
            findings.append({"type": "URL SHORTENER", "severity": "medium",
                              "detail": f"URL shortened via {domain} — true destination hidden."})

        # ── 4. Suspicious keywords in domain/path ─────────────────
        keyword_hits = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in domain or kw in path]
        if keyword_hits:
            s = min(10, len(keyword_hits) * 3)
            score += s
            findings.append({"type": "PHISHING KEYWORDS", "severity": "medium",
                              "detail": f"Suspicious keywords in URL: {', '.join(keyword_hits[:5])}"})

        # ── 5. Suspicious TLD ─────────────────────────────────────
        for tld in _SUSPICIOUS_TLD:
            if domain.endswith(tld):
                score += 8
                findings.append({"type": "HIGH-RISK TLD", "severity": "high",
                                  "detail": f"Domain uses high-risk TLD: {domain}"})
                break

        # ── 6. Subdomain depth (e.g. login.paypal.com.evilsite.ru) ─
        parts = domain.split(".")
        if len(parts) > 4:
            score += 6
            findings.append({"type": "EXCESSIVE SUBDOMAINS", "severity": "medium",
                              "detail": f"URL has {len(parts)-2} subdomain levels — common in phishing kits."})

        # ── 7. Homoglyph / typosquatting ─────────────────────────
        brands = ["paypal","microsoft","amazon","google","apple","facebook",
                  "netflix","bankofamerica","wellsfargo","chase","citibank","hsbc"]
        for brand in brands:
            if brand not in domain and self._levenshtein_close(brand, domain.split(".")[0]):
                score += 10
                findings.append({"type": "TYPOSQUATTING", "severity": "high",
                                  "detail": f"Domain '{domain}' appears to impersonate '{brand}'."})
                break

        # ── 8. VirusTotal (if API key provided) ───────────────────
        if self.vt_api_key:
            vt_result = self._check_virustotal(url)
            if vt_result:
                vt_data = vt_result
                mal = vt_result.get("malicious", 0)
                if mal >= 5:
                    score += 20
                    findings.append({"type": "VIRUSTOTAL MALICIOUS", "severity": "critical",
                                     "detail": f"VirusTotal: {mal} engines flagged this URL as malicious."})
                elif mal >= 1:
                    score += 10
                    findings.append({"type": "VIRUSTOTAL SUSPICIOUS", "severity": "high",
                                     "detail": f"VirusTotal: {mal} engine(s) flagged this URL."})

        return min(30, score), findings, vt_data

    # ──────────────────────────────────────────────────────────────
    def _check_virustotal(self, url: str) -> dict:
        """Query VirusTotal URL scan API v3."""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            headers = {"x-apikey": self.vt_api_key, "Accept": "application/json"}
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=8
            )
            if resp.status_code == 200:
                data  = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious"  : stats.get("malicious", 0),
                    "suspicious" : stats.get("suspicious", 0),
                    "harmless"   : stats.get("harmless", 0),
                    "undetected" : stats.get("undetected", 0),
                }
            time.sleep(15)  # VT free tier rate limit
        except Exception as exc:
            logger.warning("VirusTotal check failed for %s: %s", url[:60], exc)
        return {}

    def _levenshtein_close(self, a: str, b: str, max_dist: int = 2) -> bool:
        if abs(len(a) - len(b)) > max_dist:
            return False
        dp = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            ndp = [i + 1]
            for j, cb in enumerate(b):
                ndp.append(min(dp[j] + (ca != cb), dp[j+1] + 1, ndp[j] + 1))
            dp = ndp
        return dp[-1] <= max_dist and dp[-1] > 0
