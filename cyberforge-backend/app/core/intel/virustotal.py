"""
CyberForge — VirusTotal API v3 Client
Queries VT for hash reputation, domain/IP intelligence.
"""
import requests
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("cyberforge.virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    found:             bool = False
    detection_ratio:   str  = "0/0"
    total_engines:     int  = 0
    malicious_engines: int  = 0
    suspicious_engines:int  = 0
    harmless_engines:  int  = 0
    threat_names:      list[str] = field(default_factory=list)
    threat_categories: list[str] = field(default_factory=list)
    first_seen:        Optional[str] = None
    last_seen:         Optional[str] = None
    file_type:         Optional[str] = None
    tags:              list[str] = field(default_factory=list)
    vt_link:           Optional[str] = None
    error:             Optional[str] = None

    @property
    def verdict(self) -> str:
        if not self.found:
            return "UNKNOWN"
        if self.malicious_engines >= 10:
            return "MALICIOUS"
        if self.malicious_engines >= 3:
            return "SUSPICIOUS"
        if self.malicious_engines >= 1:
            return "LOW_RISK"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "found":             self.found,
            "verdict":           self.verdict,
            "detection_ratio":   self.detection_ratio,
            "total_engines":     self.total_engines,
            "malicious_engines": self.malicious_engines,
            "suspicious_engines":self.suspicious_engines,
            "harmless_engines":  self.harmless_engines,
            "threat_names":      self.threat_names,
            "threat_categories": self.threat_categories,
            "first_seen":        self.first_seen,
            "last_seen":         self.last_seen,
            "file_type":         self.file_type,
            "tags":              self.tags,
            "vt_link":           self.vt_link,
            "error":             self.error,
        }


class VirusTotalClient:
    def __init__(self, api_key: str, max_retries: int = 2, timeout: int = 15):
        self.api_key = api_key
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
        })

    def _get(self, endpoint: str) -> Optional[dict]:
        url = f"{VT_BASE}/{endpoint}"
        for attempt in range(self.max_retries):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 404:
                    return None
                if resp.status_code == 429:
                    # Rate limited — wait 60s
                    wait = int(resp.headers.get("Retry-After", 60))
                    logger.warning(f"VT rate limited. Waiting {wait}s...")
                    time.sleep(min(wait, 60))
                    continue
                logger.error(f"VT API error {resp.status_code}: {resp.text[:200]}")
            except requests.exceptions.Timeout:
                logger.warning(f"VT request timeout (attempt {attempt+1})")
            except requests.exceptions.RequestException as e:
                logger.error(f"VT request error: {e}")
        return None

    def lookup_hash(self, sha256: str) -> VTResult:
        """Look up a file hash on VirusTotal."""
        if not self.api_key:
            result = VTResult()
            result.error = "VirusTotal API key not configured"
            return result

        data = self._get(f"files/{sha256}")
        if data is None:
            result = VTResult(found=False)
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Extract threat names from analysis results
        names = set()
        cats  = set()
        for engine, result in attrs.get("last_analysis_results", {}).items():
            if result.get("category") in ("malicious", "suspicious"):
                if result.get("result"):
                    names.add(result["result"])
                if result.get("category"):
                    cats.add(result["category"])

        # Parse dates
        first_seen = attrs.get("first_submission_date")
        last_seen  = attrs.get("last_submission_date")
        if first_seen:
            from datetime import datetime
            first_seen = datetime.utcfromtimestamp(first_seen).strftime("%Y-%m-%d")
        if last_seen:
            from datetime import datetime
            last_seen  = datetime.utcfromtimestamp(last_seen).strftime("%Y-%m-%d")

        return VTResult(
            found=True,
            detection_ratio=f"{malicious}/{total}",
            total_engines=total,
            malicious_engines=malicious,
            suspicious_engines=suspicious,
            harmless_engines=harmless,
            threat_names=sorted(names)[:10],
            threat_categories=sorted(cats),
            first_seen=first_seen,
            last_seen=last_seen,
            file_type=attrs.get("type_description"),
            tags=attrs.get("tags", [])[:10],
            vt_link=f"https://www.virustotal.com/gui/file/{sha256}",
        )

    def lookup_domain(self, domain: str) -> dict:
        """Query VT for domain reputation."""
        data = self._get(f"domains/{domain}")
        if data is None:
            return {"found": False, "domain": domain}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        total      = malicious + suspicious + harmless + stats.get("undetected", 0)

        # Derive verdict from malicious engine count
        if malicious >= 5:
            verdict = "MALICIOUS"
        elif malicious >= 2:
            verdict = "SUSPICIOUS"
        elif malicious >= 1:
            verdict = "LOW_RISK"
        else:
            verdict = "CLEAN"

        return {
            "found":             True,
            "domain":            domain,
            "malicious":         malicious,
            "suspicious":        suspicious,
            "harmless":          harmless,
            "total_engines":     total,
            "detection_ratio":   f"{malicious}/{total}" if total else "0/0",
            "verdict":           verdict,
            "categories":        attrs.get("categories", {}),
            "tags":              attrs.get("tags", []),
            "vt_link":           f"https://www.virustotal.com/gui/domain/{domain}",
        }

    def lookup_domain_batch(self, domains: list, max_domains: int = 3) -> dict:
        """
        Look up up to `max_domains` domains on VirusTotal with rate-limit-aware
        delays between requests (free tier: 4 lookups/min → 15s between requests).

        Args:
            domains:     List of domain strings to look up
            max_domains: Maximum domains to query (default 3 to stay inside VT quota)

        Returns:
            Dict mapping domain → lookup result dict
        """
        if not self.api_key:
            return {}

        results = {}
        targets = [d for d in domains if d][:max_domains]

        for idx, domain in enumerate(targets):
            try:
                result = self.lookup_domain(domain)
                results[domain] = result
                logger.info(
                    f"VT domain [{idx+1}/{len(targets)}] {domain}: "
                    f"{result.get('verdict', 'N/A')} ({result.get('detection_ratio', '?')})"
                )
            except Exception as e:
                logger.error(f"VT domain lookup failed for {domain}: {e}")
                results[domain] = {"found": False, "domain": domain, "error": str(e)}

            # Respect VT free-tier rate limit: 4 req/min → wait 16s between lookups
            # (skip sleep after the last item)
            if idx < len(targets) - 1:
                time.sleep(16)

        return results

    def lookup_ip(self, ip: str) -> dict:
        """Query VT for IP reputation."""
        data = self._get(f"ip_addresses/{ip}")
        if data is None:
            return {"found": False, "ip": ip}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "found":      True,
            "ip":         ip,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country":    attrs.get("country", ""),
            "asn":        attrs.get("asn", ""),
            "as_owner":   attrs.get("as_owner", ""),
            "tags":       attrs.get("tags", []),
            "vt_link":    f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
