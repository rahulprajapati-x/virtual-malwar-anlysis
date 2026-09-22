"""
CyberForge — Free IP Geolocation Engine
Uses ip-api.com batch endpoint (no API key required, 100 req/min free tier).

Returns per-IP: country, countryCode, region, city, ISP, org, ASN,
                proxy/VPN detection, datacenter hosting detection.

Datacenter-hosted IPs are flagged as HIGH risk (likely C2 infrastructure).
"""
import logging
import requests
from dataclasses import dataclass, field
from typing import Optional, List, Dict

logger = logging.getLogger("cyberforge.ip_geo")

IP_API_BATCH_URL = "https://ip-api.com/batch"
IP_API_SINGLE_URL = "http://ip-api.com/json/{ip}"

# Fields to request from ip-api.com
_FIELDS = (
    "query,status,country,countryCode,region,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile"
)


@dataclass
class GeoResult:
    ip:           str  = ""
    status:       str  = "fail"   # "success" or "fail"
    country:      str  = ""
    country_code: str  = ""       # ISO 3166-1 alpha-2 (e.g. "US", "RU", "CN")
    region:       str  = ""
    city:         str  = ""
    isp:          str  = ""
    org:          str  = ""
    asn:          str  = ""       # e.g. "AS13335 Cloudflare, Inc."
    latitude:     float = 0.0
    longitude:    float = 0.0
    timezone:     str  = ""
    is_proxy:     bool = False    # VPN / proxy / TOR exit
    is_datacenter:bool = False    # Hosting provider / data center (C2 flag)
    is_mobile:    bool = False

    # Computed risk
    c2_risk:      str  = "UNKNOWN"   # HIGH / MEDIUM / LOW / CLEAN
    c2_reason:    str  = ""

    # Country flag emoji (computed)
    flag:         str  = ""

    error:        Optional[str] = None

    def __post_init__(self):
        if self.country_code:
            self.flag = _country_flag(self.country_code)
        self._compute_risk()

    def _compute_risk(self):
        """Assign C2 risk level based on geo characteristics."""
        if self.is_datacenter and self.is_proxy:
            self.c2_risk = "HIGH"
            self.c2_reason = "Datacenter-hosted proxy/VPN — very common C2 pivot infrastructure"
        elif self.is_datacenter:
            self.c2_risk = "HIGH"
            self.c2_reason = f"Hosted in datacenter ({self.isp or self.org}) — typical C2/bulletproof hosting"
        elif self.is_proxy:
            self.c2_risk = "MEDIUM"
            self.c2_reason = "VPN or proxy endpoint — attacker anonymization technique"
        elif self.country_code in _HIGH_RISK_COUNTRIES:
            self.c2_risk = "MEDIUM"
            self.c2_reason = f"IP origin: {self.country} — frequently associated with malicious campaigns"
        elif self.status == "success":
            self.c2_risk = "LOW"
            self.c2_reason = f"Residential/commercial IP in {self.country}"
        else:
            self.c2_risk = "UNKNOWN"
            self.c2_reason = "Geolocation lookup failed"

    def to_dict(self) -> dict:
        return {
            "ip":            self.ip,
            "status":        self.status,
            "country":       self.country,
            "country_code":  self.country_code,
            "flag":          self.flag,
            "region":        self.region,
            "city":          self.city,
            "isp":           self.isp,
            "org":           self.org,
            "asn":           self.asn,
            "latitude":      self.latitude,
            "longitude":     self.longitude,
            "timezone":      self.timezone,
            "is_proxy":      self.is_proxy,
            "is_datacenter": self.is_datacenter,
            "is_mobile":     self.is_mobile,
            "c2_risk":       self.c2_risk,
            "c2_reason":     self.c2_reason,
            "error":         self.error,
        }


# Countries commonly associated with malicious C2 infrastructure
_HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "NG", "UA", "RO", "BR", "IN",
    "VN", "TR", "BD", "PK", "TH", "ID", "EG",
}


def _country_flag(code: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E0 + ord(code[0]) - ord('A')) + chr(0x1F1E0 + ord(code[1]) - ord('A'))
    except Exception:
        return "🌐"


def _parse_single(data: dict) -> GeoResult:
    """Parse one ip-api.com response dict into a GeoResult."""
    result = GeoResult(
        ip=data.get("query", ""),
        status=data.get("status", "fail"),
        country=data.get("country", ""),
        country_code=data.get("countryCode", ""),
        region=data.get("regionName", ""),
        city=data.get("city", ""),
        isp=data.get("isp", ""),
        org=data.get("org", ""),
        asn=data.get("as", ""),
        latitude=float(data.get("lat", 0)),
        longitude=float(data.get("lon", 0)),
        timezone=data.get("timezone", ""),
        is_proxy=bool(data.get("proxy", False)),
        is_datacenter=bool(data.get("hosting", False)),
        is_mobile=bool(data.get("mobile", False)),
    )
    return result


def geolocate_ips(ips: List[str], timeout: int = 10) -> Dict[str, GeoResult]:
    """
    Geolocate a list of IP addresses using ip-api.com batch endpoint.
    No API key required. Rate limit: 100 requests/min on free tier.

    Args:
        ips:     List of IPv4 addresses to lookup
        timeout: HTTP request timeout in seconds

    Returns:
        Dict mapping IP → GeoResult
    """
    if not ips:
        return {}

    results: Dict[str, GeoResult] = {}

    # ip-api.com batch accepts up to 100 IPs per request
    batch = [ip for ip in ips if ip][:100]

    try:
        payload = [{"query": ip, "fields": _FIELDS} for ip in batch]
        resp = requests.post(
            IP_API_BATCH_URL,
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                geo = _parse_single(item)
                if geo.ip:
                    results[geo.ip] = geo
        else:
            logger.warning(f"ip-api.com batch returned {resp.status_code}")
            # Fall back to individual lookups for first 5
            for ip in batch[:5]:
                results[ip] = geolocate_single(ip, timeout)

    except requests.exceptions.Timeout:
        logger.warning("ip-api.com batch request timed out")
        # Try individual for first 3
        for ip in batch[:3]:
            try:
                results[ip] = geolocate_single(ip, timeout=5)
            except Exception:
                pass
    except Exception as e:
        logger.error(f"ip-api.com batch error: {e}")

    return results


def geolocate_single(ip: str, timeout: int = 8) -> GeoResult:
    """
    Geolocate a single IP using ip-api.com (GET request, no API key).
    Use this only as a fallback when batch fails.
    """
    result = GeoResult(ip=ip)
    try:
        url = IP_API_SINGLE_URL.format(ip=ip)
        resp = requests.get(
            url,
            params={"fields": _FIELDS},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return _parse_single(data)
            else:
                result.error = data.get("message", "Lookup failed")
        else:
            result.error = f"HTTP {resp.status_code}"
    except Exception as e:
        result.error = str(e)
    return result


def classify_domain_risk(domain: str, is_ddns: bool = False) -> dict:
    """
    Classify a domain's C2 risk level based on structural features.
    Does NOT require internet access — pure heuristics.

    Returns dict with: c2_score (0-100), risk_level, reasons list
    """
    import re
    score = 0
    reasons = []

    domain_lower = domain.lower()

    # DDNS providers are HIGH risk
    if is_ddns:
        score += 60
        reasons.append("Dynamic DNS domain — common C2 infrastructure")

    # Very short domain (DGA-like)
    parts = domain_lower.split(".")
    if len(parts) >= 2:
        sld = parts[-2]  # second-level domain
        if len(sld) <= 5 and sld.isalpha():
            score += 10
            reasons.append(f"Short domain label '{sld}' — possibly DGA-generated")

        # High consonant ratio (DGA indicator)
        vowels = set("aeiou")
        consonant_ratio = sum(1 for c in sld if c.isalpha() and c not in vowels) / max(len(sld), 1)
        if consonant_ratio > 0.75 and len(sld) > 6:
            score += 20
            reasons.append(f"High consonant ratio in '{sld}' — possible DGA domain")

        # Suspicious TLDs
        tld = parts[-1]
        if tld in {"onion", "xyz", "top", "cc", "pw", "tk", "club", "work", "online", "site"}:
            score += 20
            reasons.append(f"Suspicious TLD '.{tld}' — commonly abused for C2")

        # Random-looking domain (high entropy)
        if len(sld) > 8:
            import math
            char_freq = {}
            for c in sld:
                char_freq[c] = char_freq.get(c, 0) + 1
            entropy = -sum((f/len(sld)) * math.log2(f/len(sld)) for f in char_freq.values())
            if entropy > 3.5:
                score += 25
                reasons.append(f"High entropy domain name (entropy={entropy:.2f}) — likely DGA")

    # Numeric-heavy domain
    digits = sum(1 for c in domain if c.isdigit())
    if digits > 5:
        score += 10
        reasons.append("Many numeric characters — possible C2 pattern")

    # Subdomain depth (more subdomains = higher risk)
    subdomain_count = len(parts) - 2
    if subdomain_count >= 4:
        score += 15
        reasons.append(f"{subdomain_count} subdomains — possible DNS tunneling")

    # Map score to risk level
    score = min(score, 100)
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    return {
        "domain":     domain,
        "c2_score":   score,
        "risk_level": risk_level,
        "reasons":    reasons,
        "is_ddns":    is_ddns,
    }
