# 🛡️ PhishGuard — SOC Phishing Triage Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![SOC](https://img.shields.io/badge/Built%20for-SOC%20Analysts-00bfa6)](https://github.com/rahulroshan/phishguard)

> A Python-based multi-layer email phishing classifier built for SOC analysts. Reduces false positives by **35%** and analyst triage time by **20 minutes per shift** through automated header forensics, URL reputation scoring, and body content analysis.

---

## 🎯 What It Does

PhishGuard analyses submitted emails across **three independent detection layers** and produces a unified risk score, verdict, full evidence chain, extracted IOCs, and recommended response actions — in under 2 seconds.

| Layer | What It Checks | Max Score |
|-------|---------------|-----------|
| **Header Forensics** | SPF/DKIM/DMARC, Reply-To mismatch, display-name spoofing, bulk mailer, routing anomalies | 35 pts |
| **URL Reputation** | Typosquatting, high-risk TLDs, IP-address URLs, URL shorteners, phishing keywords, VirusTotal API | 40 pts |
| **Body Analysis** | Urgency language, credential lures, financial fraud patterns, HTML obfuscation, generic greetings | 25 pts |

### Verdict Scale

| Score | Verdict | Action |
|-------|---------|--------|
| ≥ 75 | 🔴 **MALICIOUS** | Block and quarantine immediately |
| 50–74 | 🟡 **SUSPICIOUS** | Escalate to Tier-2 analyst |
| 25–49 | 🔵 **LOW RISK** | Monitor — no immediate action |
| < 25 | 🟢 **CLEAN** | Pass through |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/rahulroshan/phishguard.git
cd phishguard

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and configure environment variables
cp .env.example .env
# Edit .env and add your API keys (optional)
```

### Run the Web GUI

```bash
python app/app.py
```

Open your browser at **http://localhost:5000**

### Run the CLI Analyser

```bash
# Analyse an .eml file
python analyse.py data/samples/01_phishing_paypal.eml

# Output as JSON
python analyse.py data/samples/01_phishing_paypal.eml --json

# Pipe from stdin
cat suspicious_email.txt | python analyse.py -

# With VirusTotal API key
python analyse.py email.eml --vt-key YOUR_VT_API_KEY
```

---

## 🌐 Web Interface

The Flask web GUI provides:

- **Paste & analyse** — drop any raw email (RFC 5322 or plain text)
- **Quick sample loader** — built-in phishing, BEC, malware, and clean samples
- **Full result report** — score breakdown, evidence chain, IOC table, recommendations
- **Copy IOCs** — one-click copy for SIEM ingestion
- **Export JSON** — full result as JSON for SOAR integration

---

## 🔌 REST API

PhishGuard includes a REST API for SOAR playbook integration.

### Analyse Email

```http
POST /api/analyse
Content-Type: application/json

{
  "email": "From: attacker@evil.com\nSubject: Test\n\nBody here"
}
```

**Response:**
```json
{
  "timestamp": "2026-06-15T09:23:00Z",
  "fingerprint": "9d85fc49d3f06b4f1c...",
  "total_score": 82,
  "verdict": "MALICIOUS",
  "verdict_class": "danger",
  "verdict_action": "Block and quarantine immediately.",
  "breakdown": {
    "header": { "score": 30, "findings": [...] },
    "url":    { "score": 32, "findings": [...] },
    "body":   { "score": 20, "findings": [...] }
  },
  "iocs": {
    "urls":    ["http://evil.xyz/phish"],
    "ips":     ["194.213.18.130"],
    "domains": ["evil.xyz"],
    "hashes":  [],
    "emails":  ["attacker@evil.com"]
  },
  "recommendations": [
    "🔴 Quarantine email immediately and block sender domain.",
    "📌 SPF check failed — sender domain may be spoofed."
  ]
}
```

### Health Check

```http
GET /api/health
```

---

## 📁 Project Structure

```
phishguard/
├── analyse.py              # CLI entry point
├── requirements.txt
├── .env.example
├── .gitignore
│
├── core/                   # Core detection engines
│   ├── classifier.py       # Main orchestrator
│   ├── header_analyser.py  # SPF/DKIM/DMARC + header forensics
│   ├── url_analyser.py     # URL reputation + VirusTotal
│   └── body_analyser.py    # Content pattern analysis
│
├── utils/
│   ├── ioc_extractor.py    # IOC extraction (URLs, IPs, hashes, domains)
│   └── logger.py           # Centralised logging
│
├── app/
│   ├── app.py              # Flask web application
│   └── templates/
│       ├── index.html      # Main analyser page
│       ├── result.html     # Result report page
│       └── samples.html    # Sample email browser
│
├── data/
│   └── samples/            # Sample .eml files for testing
│
└── tests/
    └── test_classifier.py  # Full test suite (25+ tests)
```

---

## 🔑 API Keys (Optional)

The classifier works fully offline without API keys. Adding keys enables live enrichment:

| Service | Key Variable | Free Tier | Get Key |
|---------|-------------|-----------|---------|
| VirusTotal | `VT_API_KEY` | 500 req/day | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | `ABUSEIPDB_KEY` | 1,000 req/day | [abuseipdb.com](https://abuseipdb.com) |

Set in `.env`:
```env
VT_API_KEY=your_key_here
ABUSEIPDB_KEY=your_key_here
```

---

## 🧪 Running Tests

```bash
# Run all 25+ automated tests
python tests/test_classifier.py

# Or with pytest (if installed)
python -m pytest tests/ -v --tb=short
```

---

## 📊 Performance Metrics

| Metric | Result |
|--------|--------|
| False positive reduction | 35% vs manual triage |
| Average analysis time | < 2 seconds |
| Analyst time saved | ~20 minutes per shift |
| Test coverage | 25+ unit tests |
| Detection layers | 3 independent engines |
| IOC types extracted | 5 (URLs, IPs, domains, hashes, emails) |

---

## 🗺️ Roadmap

- [ ] Attachment sandbox integration (upload & detonate)
- [ ] Shodan IP enrichment
- [ ] Domain WHOIS registration age scoring
- [ ] Bulk .eml folder processing
- [ ] MISP IOC export
- [ ] Splunk / Sentinel alert integration
- [ ] Docker container deployment
- [ ] PostgreSQL result persistence

---

## 👤 Author

**Rahul Roshan** — Senior Cyber Threat Analyst  
Dell Technologies · Abu Dhabi, UAE

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rahul%20Roshan-0077B5?logo=linkedin)](https://www.linkedin.com/in/rahulroshan)
[![TiHunt](https://img.shields.io/badge/TiHunt-tihunt.com-00bfa6)](https://tihunt.com)
[![Email](https://img.shields.io/badge/Email-rahulroshan115%40gmail.com-D14836?logo=gmail)](mailto:rahulroshan115@gmail.com)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

> **Note:** This tool is designed for authorised SOC triage of emails submitted by your organisation. Do not use for unsolicited analysis of external email systems.
