"""
CyberForge — AbuseIPDB v2 Client
Checks IP reputation against the AbuseIPDB community threat database.
"""
import requests
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("cyberforge.abuseipdb")

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseIPResult:
    ip:             str = ""
    found:          bool = False
    abuse_score:    int  = 0          # 0–100 confidence of abuse
    usage_type:     str  = ""
    isp:            str  = ""
    country_code:   str  = ""
    country_name:   str  = ""
    domain:         str  = ""
    total_reports:  int  = 0
    num_reporters:  int  = 0
    last_reported:  Optional[str] = None
    is_tor:         bool = False
    is_public:      bool = True
    verdict:        str  = "UNKNOWN"
    error:          Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip":            self.ip,
            "found":         self.found,
            "abuse_score":   self.abuse_score,
            "verdict":       self.verdict,
            "usage_type":    self.usage_type,
            "isp":           self.isp,
            "country_code":  self.country_code,
            "country_name":  self.country_name,
            "domain":        self.domain,
            "total_reports": self.total_reports,
            "num_reporters": self.num_reporters,
            "last_reported": self.last_reported,
            "is_tor":        self.is_tor,
            "is_public":     self.is_public,
            "error":         self.error,
        }


class AbuseIPDBClient:
    def __init__(self, api_key: str, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json",
        })

    def check_ip(self, ip: str, max_age_days: int = 90) -> AbuseIPResult:
        """
        Check a single IP address against AbuseIPDB.

        Args:
            ip:           The IP address to check
            max_age_days: Only consider reports in the last N days

        Returns:
            AbuseIPResult with reputation data
        """
        result = AbuseIPResult(ip=ip)

        if not self.api_key:
            result.error = "AbuseIPDB API key not configured"
            return result

        # Skip private/reserved IPs
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                result.error = "Private/reserved IP — skipping"
                return result
        except ValueError:
            result.error = f"Invalid IP address: {ip}"
            return result

        try:
            resp = self.session.get(
                f"{ABUSEIPDB_BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                result.error = f"API error {resp.status_code}"
                return result

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            # Determine verdict
            if score >= 75:
                verdict = "MALICIOUS"
            elif score >= 30:
                verdict = "SUSPICIOUS"
            elif score >= 5:
                verdict = "LOW_RISK"
            else:
                verdict = "CLEAN"

            result.found        = True
            result.abuse_score  = score
            result.verdict      = verdict
            result.usage_type   = data.get("usageType", "")
            result.isp          = data.get("isp", "")
            result.country_code = data.get("countryCode", "")
            result.country_name = data.get("countryName", "")
            result.domain       = data.get("domain", "")
            result.total_reports= data.get("totalReports", 0)
            result.num_reporters= data.get("numDistinctUsers", 0)
            result.last_reported= data.get("lastReportedAt")
            result.is_tor       = data.get("isTor", False)
            result.is_public    = data.get("isPublic", True)

        except requests.exceptions.Timeout:
            result.error = "AbuseIPDB request timed out"
        except Exception as e:
            result.error = str(e)
            logger.error(f"AbuseIPDB error for {ip}: {e}")

        return result

    def check_bulk(self, ips: list[str]) -> dict[str, AbuseIPResult]:
        """Check multiple IPs. Returns dict keyed by IP. Cap at 15 to match static_analyzer coverage."""
        return {ip: self.check_ip(ip) for ip in ips[:15]}
