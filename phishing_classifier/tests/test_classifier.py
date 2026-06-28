"""
tests/test_classifier.py
Automated test suite for PhishGuard classifier.
Run: python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.classifier    import PhishingClassifier
from core.header_analyser import HeaderAnalyser
from core.body_analyser   import BodyAnalyser
from core.url_analyser    import URLAnalyser
from utils.ioc_extractor  import IOCExtractor

clf = PhishingClassifier()

# ═══════════════════════════════════════════════════════════════
# Sample email fixtures
# ═══════════════════════════════════════════════════════════════

PHISHING_EMAIL = """From: "PayPal Security" <noreply@paypa1-secure.xyz>
To: victim@company.com
Subject: URGENT: Your account has been suspended
Date: Mon, 15 Jun 2026 09:23:00 +0000
Reply-To: support@free-email-support.tk
Authentication-Results: spf=fail; dkim=none; dmarc=fail

Dear Customer,

Your PayPal account has been SUSPENDED! Verify your identity within 24 hours or your account will be permanently closed.

Click here: http://paypa1-secure.xyz/login/verify?token=abc123

Enter your username, password, and credit card details to confirm.

PayPal Security Team"""

BEC_EMAIL = """From: "CEO Jane Smith" <jane.smith@company-corp.net>
To: finance@company.com
Subject: Urgent Wire Transfer
Reply-To: ceo.real@gmail.com
Authentication-Results: spf=fail; dkim=none

Hi,

Process a $50,000 wire transfer to this account immediately. Do not discuss with anyone.

Account: 1234567890
Bank: Overseas National Bank
SWIFT: ONBUS12

Jane"""

CLEAN_EMAIL = """From: "IT Team" <it@company.com>
To: user@company.com
Subject: Scheduled Maintenance
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Hello,

We have scheduled maintenance this Saturday from 2am to 4am UTC.
No action required.

IT Team"""

MALWARE_EMAIL = """From: hr@company.com
To: all@company.com
Subject: Updated Policy Document

Dear Employee,

Please open the attached file: EmployeeHandbook2026.exe

This is required for all staff.
Download it here: http://evilsite.tk/payloads/update.exe

HR"""


# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════

class TestClassifier:

    def test_phishing_verdict(self):
        result = clf.classify(PHISHING_EMAIL)
        assert result["verdict"] in ("MALICIOUS", "SUSPICIOUS"), \
            f"Expected MALICIOUS/SUSPICIOUS, got {result['verdict']} (score={result['total_score']})"
        assert result["total_score"] >= 50

    def test_clean_verdict(self):
        result = clf.classify(CLEAN_EMAIL)
        assert result["total_score"] < 50, \
            f"Clean email scored too high: {result['total_score']}"

    def test_bec_detected(self):
        result = clf.classify(BEC_EMAIL)
        assert result["total_score"] >= 30

    def test_score_range(self):
        for email in [PHISHING_EMAIL, BEC_EMAIL, CLEAN_EMAIL, MALWARE_EMAIL]:
            result = clf.classify(email)
            assert 0 <= result["total_score"] <= 100

    def test_iocs_extracted(self):
        result = clf.classify(PHISHING_EMAIL)
        iocs = result["iocs"]
        assert len(iocs["urls"]) > 0, "Should extract URLs from phishing email"
        assert len(iocs["emails"]) > 0 or len(iocs["domains"]) > 0

    def test_recommendations_present(self):
        result = clf.classify(PHISHING_EMAIL)
        assert len(result["recommendations"]) > 0

    def test_fingerprint_format(self):
        result = clf.classify(PHISHING_EMAIL)
        assert len(result["fingerprint"]) == 64  # SHA-256 hex

    def test_result_keys(self):
        result = clf.classify(CLEAN_EMAIL)
        required = ["timestamp","fingerprint","total_score","verdict","breakdown","iocs","email_meta","recommendations"]
        for k in required:
            assert k in result, f"Missing key: {k}"


class TestHeaderAnalyser:

    def test_spf_fail_scores(self):
        ha     = HeaderAnalyser()
        result = ha.analyse({"Authentication-Results": "spf=fail dkim=none dmarc=fail"}, "")
        assert result["score"] >= 10
        assert result.get("spf_fail")

    def test_clean_headers(self):
        ha     = HeaderAnalyser()
        result = ha.analyse({"Authentication-Results": "spf=pass dkim=pass dmarc=pass"}, "")
        assert result["score"] < 5

    def test_reply_to_mismatch(self):
        ha     = HeaderAnalyser()
        result = ha.analyse({
            "From": "support@paypal.com",
            "Reply-To": "harvester@evilsite.com"
        }, "")
        assert result["score"] >= 8


class TestBodyAnalyser:

    def test_credential_lure_detected(self):
        ba     = BodyAnalyser()
        result = ba.analyse("Please enter your password and credit card details to verify your account.")
        assert result.get("credential_lure")
        assert result["score"] >= 8

    def test_urgency_detected(self):
        ba     = BodyAnalyser()
        result = ba.analyse("URGENT: Your account will be suspended within 24 hours. Act now!")
        assert result["score"] >= 6

    def test_clean_body(self):
        ba     = BodyAnalyser()
        result = ba.analyse("Hi team, the meeting is scheduled for Thursday. Please attend.")
        assert result["score"] < 10


class TestURLAnalyser:

    def test_http_url_scores(self):
        ua     = URLAnalyser()
        result = ua.analyse(["http://malicious-site.xyz/login"])
        assert result["score"] > 0

    def test_clean_url(self):
        ua     = URLAnalyser()
        result = ua.analyse(["https://www.microsoft.com"])
        assert result["score"] < 15

    def test_ip_url_high_score(self):
        ua     = URLAnalyser()
        result = ua.analyse(["http://194.213.18.130/malware"])
        assert result["score"] >= 10

    def test_url_shortener_detected(self):
        ua     = URLAnalyser()
        result = ua.analyse(["https://bit.ly/abc123"])
        findings_types = [f["type"] for f in result["findings"]]
        assert "URL SHORTENER" in findings_types


class TestIOCExtractor:

    def test_url_extraction(self):
        ex  = IOCExtractor()
        res = ex.extract("Visit http://evil.xyz/phish and https://also-bad.com/page", {})
        assert len(res["urls"]) >= 2

    def test_ip_extraction(self):
        ex  = IOCExtractor()
        res = ex.extract("Connection to 194.213.18.130 was detected", {})
        assert "194.213.18.130" in res["ips"]

    def test_private_ip_excluded(self):
        ex  = IOCExtractor()
        res = ex.extract("Internal host at 192.168.1.1", {})
        assert "192.168.1.1" not in res["ips"]

    def test_email_extraction(self):
        ex  = IOCExtractor()
        res = ex.extract("Reply to: attacker@evil.com for more info", {})
        assert any("evil.com" in e for e in res["emails"])


# ── Run standalone ────────────────────────────────────────────
if __name__ == "__main__":
    import traceback
    tests = [TestClassifier, TestHeaderAnalyser, TestBodyAnalyser, TestURLAnalyser, TestIOCExtractor]
    passed = failed = 0
    for cls in tests:
        instance = cls()
        for name in [m for m in dir(cls) if m.startswith("test_")]:
            try:
                getattr(instance, name)()
                print(f"  ✅ {cls.__name__}.{name}")
                passed += 1
            except AssertionError as e:
                print(f"  ❌ {cls.__name__}.{name}  — {e}")
                failed += 1
            except Exception as e:
                print(f"  💥 {cls.__name__}.{name}  — {e}")
                traceback.print_exc()
                failed += 1
    print(f"\n{'='*50}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"{'='*50}\n")
    sys.exit(1 if failed else 0)
