"""
utils/ioc_extractor.py
Extracts Indicators of Compromise from email body and headers.
"""

import re
from utils.logger import get_logger

logger = get_logger(__name__)

_URL_RE    = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
_HASH_RE   = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
_EMAIL_RE  = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

_PRIVATE_RANGES = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.", "0."]


class IOCExtractor:

    def extract(self, body: str, headers: dict) -> dict:
        combined = body + " " + " ".join(str(v) for v in headers.values())

        urls    = self._extract_urls(combined)
        ips     = self._extract_ips(combined)
        domains = self._extract_domains(combined, urls)
        hashes  = list(set(_HASH_RE.findall(combined)))
        emails  = list(set(_EMAIL_RE.findall(combined)))

        return {
            "urls"    : urls[:20],
            "ips"     : ips[:10],
            "domains" : domains[:15],
            "hashes"  : hashes[:10],
            "emails"  : emails[:10],
        }

    def _extract_urls(self, text: str) -> list:
        raw = _URL_RE.findall(text)
        clean = []
        for u in raw:
            u = u.rstrip(".,;:\"')")
            if len(u) > 8 and u not in clean:
                clean.append(u)
        return clean[:20]

    def _extract_ips(self, text: str) -> list:
        raw = _IP_RE.findall(text)
        return [ip for ip in set(raw)
                if not any(ip.startswith(p) for p in _PRIVATE_RANGES)][:10]

    def _extract_domains(self, text: str, urls: list) -> list:
        from urllib.parse import urlparse
        url_domains = set()
        for u in urls:
            try:
                p = urlparse(u if u.startswith("http") else "http://" + u)
                if p.netloc:
                    url_domains.add(p.netloc.lower().replace("www.", ""))
            except Exception:
                pass
        raw = _DOMAIN_RE.findall(text)
        extras = [d.lower() for d in raw
                  if len(d) > 4 and "." in d and d not in url_domains]
        return list(url_domains) + list(set(extras))[:10]
