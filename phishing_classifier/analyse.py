#!/usr/bin/env python3
"""
PhishGuard CLI — Analyse emails from the command line.

Usage:
  python analyse.py email.eml
  python analyse.py email.eml --json
  python analyse.py email.eml --vt-key YOUR_VT_KEY
  cat email.txt | python analyse.py -
"""

import sys, os, json, argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from core.classifier import PhishingClassifier

def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Email Phishing Classifier",
        epilog="Example: python analyse.py suspicious.eml --json"
    )
    parser.add_argument("input", help="Email file path or '-' for stdin")
    parser.add_argument("--json",    action="store_true", help="Output raw JSON")
    parser.add_argument("--vt-key",  default=os.getenv("VT_API_KEY",""),  help="VirusTotal API key")
    parser.add_argument("--abuse-key",default=os.getenv("ABUSEIPDB_KEY",""), help="AbuseIPDB API key")
    args = parser.parse_args()

    # ── Read email ────────────────────────────────────────────────
    if args.input == "-":
        raw_email = sys.stdin.read()
    else:
        if not os.path.exists(args.input):
            print(f"[ERROR] File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            raw_email = fh.read()

    # ── Classify ──────────────────────────────────────────────────
    clf    = PhishingClassifier(vt_api_key=args.vt_key, abuseipdb_key=args.abuse_key)
    result = clf.classify(raw_email)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # ── Pretty print ──────────────────────────────────────────────
    sep = "=" * 60
    v   = result["verdict"]
    sc  = result["total_score"]

    print(f"\n{sep}")
    print(f"  PhishGuard Analysis Report")
    print(f"{sep}")
    print(f"  Verdict  : {result['verdict_icon']} {v}")
    print(f"  Score    : {sc}/100")
    print(f"  Action   : {result['verdict_action']}")
    print(f"  SHA-256  : {result['fingerprint'][:32]}...")
    print(f"  Time     : {result['timestamp']}")
    print(f"{sep}")

    meta = result["email_meta"]
    print(f"\n  From    : {meta['from']}")
    print(f"  To      : {meta['to']}")
    print(f"  Subject : {meta['subject']}")

    print(f"\n{'─'*60}")
    print("  SCORE BREAKDOWN")
    print(f"{'─'*60}")
    for key, label, mx in [("header","Header Analysis",35),("url","URL Reputation",40),("body","Body Analysis",25)]:
        s = result["breakdown"][key]["score"]
        bar = "█" * int(s/mx*20) + "░" * (20-int(s/mx*20))
        print(f"  {label:20s}  [{bar}]  {s:2d}/{mx}")

    print(f"\n{'─'*60}")
    print("  FINDINGS")
    print(f"{'─'*60}")
    for layer in ["header","url","body"]:
        for f in result["breakdown"][layer].get("findings",[]):
            sev = f["severity"].upper()
            print(f"  [{sev:8s}] {f['type']:25s}  {f['detail'][:60]}")

    iocs = result["iocs"]
    if any(iocs.values()):
        print(f"\n{'─'*60}")
        print("  EXTRACTED IOCs")
        print(f"{'─'*60}")
        for k, v in iocs.items():
            if v:
                print(f"  {k.upper():10s}: {', '.join(v[:5])}")

    print(f"\n{'─'*60}")
    print("  RECOMMENDATIONS")
    print(f"{'─'*60}")
    for r in result["recommendations"]:
        print(f"  {r}")

    print(f"\n{sep}\n")


if __name__ == "__main__":
    main()
