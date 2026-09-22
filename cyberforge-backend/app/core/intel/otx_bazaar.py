"""
CyberForge — AlienVault OTX + MalwareBazaar Threat Intelligence Clients
Real integration with two major free threat intel platforms.

OTX: Indicators, pulses, IP/domain/file hash lookups
MalwareBazaar: Hash lookups for known malware samples
"""
import logging
from typing import Optional
import httpx

from app.config import settings

logger = logging.getLogger("cyberforge.intel.otx")


class OTXResult:
    def __init__(self):
        self.pulse_count: int = 0
        self.pulses: list[dict] = []
        self.threat_score: int = 0
        self.verdict: str = "UNKNOWN"
        self.tags: list[str] = []
        self.malware_families: list[str] = []
        self.countries: list[str] = []
        self.raw: dict = {}


async def otx_lookup_hash(sha256: str, sha1: str = "", md5: str = "") -> Optional[OTXResult]:
    """
    Look up a file hash in AlienVault OTX.
    Returns OTXResult if found, None on error/no key.
    """
    api_key = settings.OTX_API_KEY
    if not api_key or api_key == "your_otx_key_here":
        return None

    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception as e:
        logger.warning(f"OTX hash lookup failed for {sha256[:8]}…: {e}")
        return None

    result = OTXResult()
    result.raw = data
    result.pulse_count = data.get("pulse_info", {}).get("count", 0)
    result.pulses = [
        {
            "name": p.get("name", ""),
            "author": p.get("author_name", ""),
            "tags": p.get("tags", []),
            "malware_families": p.get("malware_families", []),
            "created": p.get("created", ""),
        }
        for p in data.get("pulse_info", {}).get("pulses", [])[:5]
    ]

    # Collect tags and malware families
    for pulse in result.pulses:
        result.tags.extend(pulse.get("tags", []))
        result.malware_families.extend(pulse.get("malware_families", []))

    result.tags = list(set(result.tags))[:10]
    result.malware_families = list(set(result.malware_families))[:5]

    # Score based on pulse count
    if result.pulse_count >= 10:
        result.threat_score = 95
        result.verdict = "MALICIOUS"
    elif result.pulse_count >= 3:
        result.threat_score = 70
        result.verdict = "SUSPICIOUS"
    elif result.pulse_count >= 1:
        result.threat_score = 40
        result.verdict = "SUSPICIOUS"
    else:
        result.threat_score = 5
        result.verdict = "CLEAN"

    logger.info(f"OTX: {sha256[:8]}… → {result.pulse_count} pulses, verdict={result.verdict}")
    return result


async def otx_lookup_ip(ip: str) -> Optional[dict]:
    """Look up an IP address in OTX."""
    api_key = settings.OTX_API_KEY
    if not api_key or api_key == "your_otx_key_here":
        return None

    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return {
                "ip": ip,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "country": data.get("country_name", ""),
                "asn": data.get("asn", ""),
                "reputation": data.get("reputation", 0),
                "verdict": "MALICIOUS" if data.get("pulse_info", {}).get("count", 0) > 0 else "CLEAN",
            }
    except Exception as e:
        logger.warning(f"OTX IP lookup failed for {ip}: {e}")
        return None


async def otx_lookup_domain(domain: str) -> Optional[dict]:
    """Look up a domain in OTX."""
    api_key = settings.OTX_API_KEY
    if not api_key or api_key == "your_otx_key_here":
        return None

    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "domain": domain,
                "pulse_count": pulse_count,
                "alexa_rank": data.get("alexa", ""),
                "verdict": "MALICIOUS" if pulse_count > 0 else "CLEAN",
                "validation": data.get("validation", []),
            }
    except Exception as e:
        logger.warning(f"OTX domain lookup failed for {domain}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  MALWAREBAZAAR
# ─────────────────────────────────────────────────────────────────────────────

class MalwareBazaarResult:
    def __init__(self):
        self.found: bool = False
        self.sha256: str = ""
        self.file_type: str = ""
        self.file_name: str = ""
        self.file_size: int = 0
        self.signature: str = ""
        self.tags: list[str] = []
        self.reporter: str = ""
        self.first_seen: str = ""
        self.last_seen: str = ""
        self.vendor_intel: dict = {}
        self.intelligence: dict = {}
        self.verdict: str = "UNKNOWN"


async def malwarebazaar_lookup(sha256: str) -> Optional[MalwareBazaarResult]:
    """
    Look up a SHA256 hash in MalwareBazaar (no API key needed for basic lookups).
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_info", "hash": sha256}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=payload)
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception as e:
        logger.warning(f"MalwareBazaar lookup failed for {sha256[:8]}…: {e}")
        return None

    if data.get("query_status") != "ok":
        # Hash not found in MalwareBazaar
        result = MalwareBazaarResult()
        result.found = False
        result.verdict = "UNKNOWN"
        return result

    sample_data = data.get("data", [{}])[0] if data.get("data") else {}

    result = MalwareBazaarResult()
    result.found = True
    result.sha256 = sample_data.get("sha256_hash", sha256)
    result.file_type = sample_data.get("file_type", "")
    result.file_name = sample_data.get("file_name", "")
    result.file_size = sample_data.get("file_size", 0)
    result.signature = sample_data.get("signature", "")
    result.tags = sample_data.get("tags", []) or []
    result.reporter = sample_data.get("reporter", "")
    result.first_seen = sample_data.get("first_seen", "")
    result.last_seen = sample_data.get("last_seen", "")
    result.vendor_intel = sample_data.get("vendor_intel", {}) or {}
    result.intelligence = sample_data.get("intelligence", {}) or {}
    result.verdict = "MALICIOUS"  # Any hash in MalwareBazaar is confirmed malware

    logger.info(f"MalwareBazaar: {sha256[:8]}… → FOUND (signature={result.signature}, tags={result.tags[:3]})")
    return result
