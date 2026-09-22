"""
CyberForge — IOC Extractor v2.0
Extracts Indicators of Compromise from file content using regex patterns.
Covers: domains, IPs (including private/internal), URLs, emails, registry keys,
        file paths, hashes, wallets, binary-packed IPs, IP:Port, C2 patterns.
"""
import re
import struct
from pathlib import Path
from dataclasses import dataclass, field


# ── Regex patterns ─────────────────────────────────────────────────────────

_RE_URL = re.compile(
    r"(?:https?|ftp|ftps|smb|ldap|ldaps|rtsp|ws|wss)://"
    r"[^\s\"'<>\x00-\x1f]{4,300}",
    re.IGNORECASE
)

_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|onion|xyz|top|info|biz|cc|tk|pw|me|co|uk|"
    r"de|in|au|br|eu|fr|jp|kr|nl|pl|se|ch|ca|es|it|at|be|cz|dk|fi|gr|hu|"
    r"no|pt|ro|sk|ua|hk|sg|tw|vn|th|id|ph|my|za|ng|mx|ar|cl|pe|ve|"
    r"gov|mil|edu|int|ac|sch|nhs|"
    r"dyndns|no-ip|duckdns|ddns|afraid|changeip|dynip|3utilities|bounceme|"
    r"freedns|dynv6|sytes|myftp|mysecuritycamera|redirectme|serveblog|"
    r"onthewifi|serveftp|zapto|servegame|serveminecraft|hopto)"
    r"\b",
    re.IGNORECASE
)

_RE_IP = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|[1-9])\."  # first octet: must be 1-255
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."         # second octet: 0-255
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."         # third octet: 0-255
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d))\b"        # fourth octet: 0-255
)

# IP:Port pattern (e.g. 192.168.1.1:4444 or 10.0.0.1:8080)
_RE_IP_PORT = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"[:\x00]"                              # colon or null separator (wide strings)
    r"(?P<port>\d{1,5})\b"
)

_RE_EMAIL    = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_REGKEY   = re.compile(
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
    r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:\\[^\x00\n\"<>|?*]{2,120})+",
    re.IGNORECASE
)
_RE_FILEPATH = re.compile(
    r"(?:[A-Za-z]:\\|%[A-Za-z_]+%\\?)[^\x00\n\"<>|?*]{4,200}",
    re.IGNORECASE
)
_RE_MUTEX    = re.compile(r"(?:Global|Local|Session)\\[A-Za-z0-9_\-\.]{4,80}")
_RE_MD5      = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA256   = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1     = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_BTC      = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
_RE_ETH      = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# C2 framework signatures (Cobalt Strike, Metasploit, Sliver, Havoc, Empire, Brute Ratel)
_RE_C2_SIGS = re.compile(
    r"(?i)(?:"
    # Cobalt Strike
    r"cobaltstrike|cobalt\s+strike|beacon\.dll|beacon\.x64|"
    r"sleep_mask|prepend_sleep|artifact\.kit|"
    r"MZ.{,500}ReflectiveDll|msvcrt\.dll.{,200}beacon|"
    r"/submit\.php|/beam\.php|/cab\.asp|/pixel\.gif\?|"
    r"heartbeat\.php|(?<!\w)cs(?:agent|beacon|stager)(?!\w)|"
    # Metasploit / Meterpreter
    r"meterpreter|metsrv\.dll|msfvenom|metasploit|"
    r"ReflectiveDllInjection|ReflectiveLoader|"
    r"windows/meterpreter|linux/x86/shell|"
    r"/multi/handler|"
    # Sliver C2
    r"sliver[_\-]implant|sliver\.exe|gogo/protobuf|"
    r"sliverpb|implants\.Implant|"
    # Havoc C2
    r"havoc[_\-]c2|teamserver|HavocC2|"
    # Brute Ratel
    r"bruteratel|brute\s+ratel|brc4|badger\.bin|"
    # Empire / PoshC2
    r"powershell\s+empire|poshc2|implant\.ps1|"
    # Common RAT indicators
    r"njrat|njRAT|darkcomet|darkRAT|asyncrat|asyncRAT|"
    r"remcos|remcosRAT|quasar|QuasarRAT|nanocore|NanoCore|"
    r"xworm|XWorm|DCRat|dcrat|"
    r"gh0st|Gh0st\s+RAT|"
    # C2 communication patterns
    r"cmd\.exe\s+/c\s+whoami|net\s+user\s+/add|"
    r"reg\s+add.*\\Run|schtasks.*/create|"
    r"certutil\s+-(?:decode|urlcache|f)|"
    r"bitsadmin\s+/transfer|"
    r"mshta\s+(?:https?://|vbscript:|javascript:)|"
    r"regsvr32\s+/s\s+/u\s+/i:|"
    r"wmic\s+process\s+call\s+create"
    r")"
)

# Dynamic DNS / free hosting domains commonly used for C2
_RE_DDNS = re.compile(
    r"\b[a-zA-Z0-9\-]+\."
    r"(?:duckdns\.org|no-ip\.(?:com|biz|org|info)|"
    r"dyndns\.(?:org|com|net|tv)|afraid\.org|freedns\.afraid\.org|"
    r"dynv6\.com|sytes\.net|myftp\.(?:biz|org)|"
    r"hopto\.org|zapto\.org|ddns\.net|"
    r"ngrok\.(?:io|app|dev)|pagekite\.me|"
    r"serveo\.net|localhost\.run|"
    r"tunnel\.(?:us|eu)|bore\.pub|"
    # Additional DDNS / free-subdomain providers
    r"dynu\.com|dynu\.net|"
    r"cloudns\.net|cloudns\.biz|cloudns\.org|"
    r"tplinkdns\.com|ns1\.name|ns2\.name|"
    r"ddnsfree\.com|gotdns\.ch|gotdns\.com|"
    r"publicvm\.com|linkpc\.net|"
    r"nsupdate\.info|dnsfor\.me|"
    r"freemyip\.com|3utilities\.com|"
    r"bounceme\.net|serveblog\.net|"
    r"onthewifi\.com|redirectme\.net)"
    r"\b",
    re.IGNORECASE
)

# Suspicious port numbers commonly used by C2/RATs
_C2_PORTS = {
    4444, 4445, 4446, 4447, 4448,   # Metasploit defaults
    1234, 1337, 31337,               # Classic hacker ports
    8080, 8443, 8888, 9090,          # HTTP alt ports
    6666, 6667, 6668, 6669,          # IRC/legacy RAT
    5555, 7777, 9999,                # Common RAT ports
    2222, 3333, 11211,               # Misc
    65535, 65000, 60000,             # High ports
    443, 80,                         # Web (legitimate but worth flagging in binary context)
    4443, 8444, 8083,                # HTTPS alt
    1080, 1081, 3128, 8118,          # Proxy/SOCKS
    9001, 9030, 9050, 9051,          # TOR
}

# IPs that are 100% noise — only absolute garbage values filtered
_NOISE_IPS = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "1.0.0.0", "2.0.0.0", "3.0.0.0",
}

# Allowlisted benign domains
_ALLOWLIST_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "apple.com", "adobe.com", "google.com", "googleapis.com",
    "gstatic.com", "github.com", "githubusercontent.com",
    "digicert.com", "verisign.com", "globalsign.com", "comodo.com",
    "mozilla.org", "firefox.com", "opera.com",
    "schema.org", "w3.org", "xml.org", "openssl.org",
    "akamai.com", "akamaiedge.net", "cloudflare.com", "fastly.com",
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_noise_ip(ip: str) -> bool:
    """Filter garbage IPs — strict validation to avoid false positives."""
    if ip in _NOISE_IPS:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True
    # All octets must be valid 0-255
    if any(o < 0 or o > 255 for o in octets):
        return True
    # First octet must be >= 1 (not 0.x.x.x)
    if octets[0] == 0:
        return True
    # All-same-octet: 1.1.1.1, 2.2.2.2 etc (version numbers in PE)
    if len(set(octets)) == 1 and octets[0] <= 5:
        return True
    # Version-number patterns like 1.0.0.0, 6.2.0.0, 10.0.0.0
    if octets[2] == 0 and octets[3] == 0 and octets[0] <= 15 and octets[1] <= 9:
        return True
    # Very low third+fourth octets that look like version numbers (e.g. 5.1.2.3)
    if octets[0] <= 9 and octets[1] <= 9:
        return True
    # Broadcast / multicast / reserved
    if octets[0] >= 224:
        return True
    return False


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC-1918 private (still reported but flagged separately)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or
            a == 127 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or
            (a == 169 and b == 254)
        )
    except ValueError:
        return False


def _is_allowlisted_domain(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in _ALLOWLIST_DOMAINS)


def _extract_binary_ips(raw: bytes) -> list[str]:
    """
    Scan for 4-byte DWORD sequences that represent valid non-noise IP addresses.
    Malware often stores C2 IPs as raw 32-bit integers (big-endian or little-endian).
    """
    found = []
    seen  = set()
    for i in range(0, len(raw) - 3, 1):
        # Try big-endian
        quad = raw[i:i+4]
        for order in ("big", "little"):
            val = int.from_bytes(quad, order)
            a = (val >> 24) & 0xFF
            b = (val >> 16) & 0xFF
            c = (val >>  8) & 0xFF
            d =  val        & 0xFF
            # Must be routable-looking: first octet >= 1, not loopback/broadcast
            if a < 1 or a == 127 or a >= 224:
                continue
            # Skip version-number patterns
            if a <= 9 and b <= 9 and c == 0 and d == 0:
                continue
            ip = f"{a}.{b}.{c}.{d}"
            if ip not in seen and ip not in _NOISE_IPS:
                seen.add(ip)
                found.append(ip)
    return found[:200]  # cap to avoid noise


@dataclass
class ExtractedIOCs:
    urls:              list[str] = field(default_factory=list)
    domains:           list[str] = field(default_factory=list)
    ips:               list[str] = field(default_factory=list)
    private_ips:       list[str] = field(default_factory=list)   # internal IPs
    ip_ports:          list[str] = field(default_factory=list)   # IP:Port combos
    emails:            list[str] = field(default_factory=list)
    registry_keys:     list[str] = field(default_factory=list)
    file_paths:        list[str] = field(default_factory=list)
    mutexes:           list[str] = field(default_factory=list)
    c2_signatures:     list[str] = field(default_factory=list)   # C2 framework sigs
    ddns_domains:      list[str] = field(default_factory=list)   # Dynamic DNS
    # Scored domains — list of {domain, c2_score, risk_level, reasons, is_ddns}
    # Populated for any domain scoring >= 30 (MEDIUM or higher)
    c2_scored_domains: list[dict] = field(default_factory=list)  # C2 confidence-scored domains
    hashes_md5:        list[str] = field(default_factory=list)
    hashes_sha1:       list[str] = field(default_factory=list)
    hashes_sha256:     list[str] = field(default_factory=list)
    crypto_wallets:    list[str] = field(default_factory=list)

    def total(self) -> int:
        return (
            len(self.urls) + len(self.domains) + len(self.ips) +
            len(self.private_ips) + len(self.ip_ports) +
            len(self.emails) + len(self.registry_keys) + len(self.file_paths) +
            len(self.mutexes) + len(self.c2_signatures) + len(self.ddns_domains) +
            len(self.crypto_wallets) +
            len(self.hashes_md5) + len(self.hashes_sha1) + len(self.hashes_sha256)
        )

    def to_dict(self) -> dict:
        return {
            "urls":              self.urls,
            "domains":          self.domains,
            "ips":              self.ips,
            "private_ips":      self.private_ips,
            "ip_ports":         self.ip_ports,
            "emails":           self.emails,
            "registry_keys":    self.registry_keys,
            "file_paths":       self.file_paths,
            "mutexes":          self.mutexes,
            "c2_signatures":    self.c2_signatures,
            "ddns_domains":     self.ddns_domains,
            "c2_scored_domains": self.c2_scored_domains,
            "hashes": {
                "md5":    self.hashes_md5,
                "sha1":   self.hashes_sha1,
                "sha256": self.hashes_sha256,
            },
            "crypto_wallets":   self.crypto_wallets,
            "total":            self.total(),
        }


def extract_strings(data: bytes, min_len: int = 4) -> str:
    """Extract all printable ASCII + wide strings from binary data."""
    ascii_pat = re.compile(rb"[ -~\t\r\n]{" + str(min_len).encode() + rb",}")
    wide_pat  = re.compile(rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}")

    ascii_strings = [s.decode("ascii", errors="ignore") for s in ascii_pat.findall(data)]
    wide_strings  = [s.decode("utf-16-le", errors="ignore") for s in wide_pat.findall(data)]

    return "\n".join(ascii_strings + wide_strings)


def extract_iocs(file_path: Path, max_bytes: int = 0) -> ExtractedIOCs:
    """
    Read a file (full file by default), extract all strings, then apply
    IOC patterns to find network indicators and forensic artifacts.
    max_bytes=0 means read the entire file.
    """
    iocs = ExtractedIOCs()

    try:
        with open(file_path, "rb") as f:
            raw = f.read() if max_bytes == 0 else f.read(max_bytes)
    except Exception:
        return iocs

    text = extract_strings(raw)

    # ── URLs ──────────────────────────────────────────────────────────────
    urls = sorted({u.rstrip(".,;)\"'") for u in _RE_URL.findall(text)})
    iocs.urls = urls[:100]

    # ── DDNS / Tunneling Domains (highest priority — flag before generic domain) ──
    ddns = sorted({d.lower() for d in _RE_DDNS.findall(text)})
    iocs.ddns_domains = ddns[:50]

    # ── Domains ───────────────────────────────────────────────────────────
    url_hosts = {re.sub(r"[a-z]+://([^/:]+).*", r"\1", u, flags=re.I) for u in iocs.urls}
    raw_domains = {d.lower() for d in _RE_DOMAIN.findall(text)}
    filtered_domains = [
        d for d in raw_domains
        if d not in url_hosts
        and not _is_allowlisted_domain(d)
        and len(d) > 4
    ]
    iocs.domains = sorted(filtered_domains)[:150]

    # ── C2 Domain Confidence Scoring ──────────────────────────────────────
    # Score DDNS domains (auto HIGH) + other domains with MEDIUM+ risk
    from app.core.intel.ip_geo import classify_domain_risk
    ddns_set = set(iocs.ddns_domains)
    scored = []
    for domain in (list(ddns_set) + [d for d in iocs.domains if d not in ddns_set])[:80]:
        result = classify_domain_risk(domain, is_ddns=(domain in ddns_set))
        if result["c2_score"] >= 30:  # Only MEDIUM or higher
            scored.append(result)
    scored.sort(key=lambda x: -x["c2_score"])
    iocs.c2_scored_domains = scored[:50]

    # ── IP Addresses (text form) ──────────────────────────────────────────
    # Use finditer to avoid group tuple issues with capturing regex
    all_text_ips = {m.group(0) for m in _RE_IP.finditer(text) if not _is_noise_ip(m.group(0))}
    public_ips  = sorted([ip for ip in all_text_ips if not _is_private_ip(ip)])
    private_ips = sorted([ip for ip in all_text_ips if _is_private_ip(ip)])
    iocs.ips         = public_ips[:100]
    iocs.private_ips = private_ips[:50]

    # ── IP:Port combos ────────────────────────────────────────────────────
    ip_port_matches = []
    for m in _RE_IP_PORT.finditer(text):
        try:
            port = int(m.group("port"))
            if 1 <= port <= 65535:
                full = m.group(0).rstrip(":")
                ip_port_matches.append(full)
        except (ValueError, IndexError):
            pass
    iocs.ip_ports = sorted(set(ip_port_matches))[:50]

    # ── C2 Framework Signatures ───────────────────────────────────────────
    c2_sigs = []
    for m in _RE_C2_SIGS.finditer(text):
        val = m.group(0).strip()
        if val and len(val) >= 4:
            c2_sigs.append(val[:120])
    iocs.c2_signatures = list({s.lower(): s for s in c2_sigs}.values())[:30]

    # ── Emails ────────────────────────────────────────────────────────────
    iocs.emails = sorted(set(_RE_EMAIL.findall(text)))[:30]

    # ── Registry Keys ─────────────────────────────────────────────────────
    iocs.registry_keys = sorted(set(_RE_REGKEY.findall(text)))[:50]

    # ── File Paths ────────────────────────────────────────────────
    legit_prefixes = (
        "c:\\windows\\system32\\", "c:\\program files\\",
        "%windir%\\system32\\", "c:\\windows\\syswow64\\",
    )
    PRINTABLE_THRESHOLD = 0.85  # at least 85% printable chars
    raw_paths = _RE_FILEPATH.findall(text)
    clean_paths = []
    for p in raw_paths:
        # Skip if too many non-printable chars (garbled/encoded)
        printable_ratio = sum(1 for c in p if 32 <= ord(c) <= 126) / max(len(p), 1)
        if printable_ratio < PRINTABLE_THRESHOLD:
            continue
        # Skip if starts with a legitimate system prefix
        if any(p.lower().startswith(pfx) for pfx in legit_prefixes):
            continue
        # Skip paths with suspicious placeholder chars (APK resource IDs)
        if any(c in p for c in ['%', '\x00', '\x01', '\x02', '\x03']):
            # Allow only known env var patterns like %AppData%
            import re as _re
            if _re.search(r'%[A-Za-z_]{3,30}%', p):
                clean_paths.append(p)
            continue
        clean_paths.append(p)
    iocs.file_paths = sorted(set(clean_paths))[:30]

    # ── Mutexes ───────────────────────────────────────────────────────────
    iocs.mutexes = sorted(set(_RE_MUTEX.findall(text)))[:20]

    # ── Crypto Wallets ────────────────────────────────────────────────────
    btc = list(set(_RE_BTC.findall(text)))
    eth = list(set(_RE_ETH.findall(text)))
    iocs.crypto_wallets = sorted(btc + eth)[:20]

    # ── File Hashes ───────────────────────────────────────────────────────
    all_sha256 = set(_RE_SHA256.findall(text))
    all_sha1   = set(_RE_SHA1.findall(text)) - all_sha256
    all_md5    = set(_RE_MD5.findall(text)) - all_sha256 - all_sha1
    iocs.hashes_sha256 = sorted(all_sha256)[:20]
    iocs.hashes_sha1   = sorted(all_sha1)[:20]
    iocs.hashes_md5    = sorted(all_md5)[:20]

    return iocs
