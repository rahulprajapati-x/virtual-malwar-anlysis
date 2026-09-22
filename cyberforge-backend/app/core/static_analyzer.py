"""
CyberForge — Static Analysis Orchestrator
Coordinates all analysis engines: hashing, PE parsing, YARA, IOC extraction,
MITRE mapping, threat intelligence lookups, and optional dynamic sandbox.

Hardened (v2) — includes:
  • Heuristic packer/obfuscation scoring (+30 per high-entropy section, etc.)
  • API combo detection (injection triad, NT evasion, ransomware pattern)
  • VT zero-day / unknown sample handling
  • Weighted static×0.4 + dynamic×0.6 score merge
  • Hard minimum floor rules (never let static override dynamic HIGH/CRITICAL)
  • VERDICT CONFLICT detection when static and dynamic differ by ≥2 levels
  • score_breakdown list for UI transparency
  • Confidence source labels on every behavior item
  • analysis_depth field: "static" or "static+dynamic"
"""
import logging
import time
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from app.core.hash_engine import compute_hashes, HashResult
from app.core.pe_parser import parse_pe, PEResult
from app.core.yara_scanner import YARAScanner, YARAScanResult
from app.core.ioc_extractor import extract_iocs, ExtractedIOCs
from app.core.mitre_mapper import map_to_attack, ATTACKTechnique
from app.core.intel.virustotal import VirusTotalClient, VTResult
from app.core.intel.abuseipdb import AbuseIPDBClient, AbuseIPResult
from app.core.intel.ip_geo import geolocate_ips, classify_domain_risk, GeoResult
from app.core.dynamic_sandbox import DynamicSandboxResult, run_dynamic_analysis

logger = logging.getLogger("cyberforge.analyzer")

# ── Risk scoring weights ────────────────────────────────────────
_EXT_BASE_RISK = {
    "exe": 45, "dll": 45, "msi": 40, "bat": 38, "ps1": 38,
    "vbs": 38, "js":  35, "hta": 40, "scr": 45, "pif": 40,
    "apk": 42, "aab": 42,
    "pdf": 22, "docx":22, "xlsx":22, "pptx":20, "doc":22, "xls":22,
    "pcap":35, "pcapng":35,
    "raw": 28, "mem": 28, "dmp": 28,
    "zip": 15, "rar": 15, "7z":  15,
    "py":  30, "sh":  30, "rb":  25,
}

_SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

# Threat level ordering for floor comparisons
_LEVEL_RANK = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# File types that must never show CLEAN
_EXE_TYPES = {"exe", "dll", "scr", "bat", "ps1", "hta", "pif", "vbs", "msi"}


@dataclass
class AnalysisReport:
    # File identity
    filename:     str = ""
    file_size:    int = 0
    file_type:    str = ""
    mime_type:    str = ""

    # Timing
    analysis_start: float = field(default_factory=time.time)
    analysis_duration_ms: int = 0

    # Risk — static-only values (stored before dynamic merge)
    static_score:       int = 0
    static_threat_level: str = "CLEAN"

    # Risk — final (after merge with dynamic if available)
    risk_score:    int  = 0
    threat_level:  str  = "CLEAN"    # CRITICAL / HIGH / MEDIUM / LOW / CLEAN

    # Analysis depth
    analysis_depth: str = "static"   # "static" or "static+dynamic"

    # Verdict reconciliation
    verdict_conflict: bool = False
    verdict_conflict_explanation: str = ""

    # Score transparency — list of {label, points, source} dicts
    score_breakdown: list[dict] = field(default_factory=list)

    # Results from each engine
    hashes:    Optional[HashResult]    = None
    pe_info:   Optional[PEResult]      = None
    yara:      Optional[YARAScanResult]= None
    iocs:      Optional[ExtractedIOCs] = None
    mitre:     list[ATTACKTechnique]   = field(default_factory=list)
    vt_result: Optional[VTResult]      = None
    abuseipdb_results: list[AbuseIPResult] = field(default_factory=list)

    # IP Geolocation results (free, no API key) — keyed by IP string
    ip_geo_results: dict = field(default_factory=dict)  # ip -> GeoResult.to_dict()

    # Domain C2 intelligence — list of {domain, c2_score, risk_level, reasons, is_ddns}
    domain_intel: list[dict] = field(default_factory=list)

    # VirusTotal domain reputation — keyed by domain string
    # Only populated when VT API key is set and HIGH-risk domains are found
    vt_domain_results: dict = field(default_factory=dict)  # domain -> vt lookup dict

    # Behaviors summary (human-readable) — each item has a "source" key
    behaviors: list[dict] = field(default_factory=list)

    # Dynamic sandbox result (optional — only populated when enable_dynamic=True)
    dynamic_result: Optional[DynamicSandboxResult] = None

    def finalize(self):
        self.analysis_duration_ms = int((time.time() - self.analysis_start) * 1000)

    def to_dict(self) -> dict:
        return {
            "filename":       self.filename,
            "file_size":      self.file_size,
            "file_type":      self.file_type,
            "mime_type":      self.mime_type,
            "risk_score":     self.risk_score,
            "threat_level":   self.threat_level,
            "static_score":   self.static_score,
            "static_threat_level": self.static_threat_level,
            "analysis_depth": self.analysis_depth,
            "verdict_conflict": self.verdict_conflict,
            "verdict_conflict_explanation": self.verdict_conflict_explanation,
            "score_breakdown": self.score_breakdown,
            "analysis_duration_ms": self.analysis_duration_ms,
            "hashes":         self.hashes.to_dict() if self.hashes else {},
            "pe_info":        self.pe_info.to_dict() if self.pe_info else None,
            "yara":           self.yara.to_dict() if self.yara else {},
            "iocs":           self.iocs.to_dict() if self.iocs else {},
            "mitre":          [t.to_dict() for t in self.mitre],
            "virustotal":     self.vt_result.to_dict() if self.vt_result else None,
            "abuseipdb":      [r.to_dict() for r in self.abuseipdb_results],
            "ip_geo_results":    self.ip_geo_results,
            "domain_intel":      self.domain_intel,
            "vt_domain_results": self.vt_domain_results,
            "behaviors":         self.behaviors,
            "dynamic":        self.dynamic_result.to_dict() if self.dynamic_result else None,
            "entropy":        getattr(self, "entropy", None),
            "strings_analysis": getattr(self, "strings_analysis", None),
            "document":       getattr(self, "document", None),
            "apk":            getattr(self, "apk", None),
            "structure":      getattr(self, "structure", None),
            "malwarebazaar":  getattr(self, "malwarebazaar", None),
            "otx":            getattr(self, "otx", None),
        }


def _detect_mime(file_path: Path) -> str:
    """Detect MIME type using python-magic if available."""
    try:
        import magic
        return magic.from_file(str(file_path), mime=True)
    except Exception:
        pass
    ext = file_path.suffix.lower().lstrip(".")
    fallback = {
        "exe": "application/x-dosexec",
        "dll": "application/x-dosexec",
        "pdf": "application/pdf",
        "zip": "application/zip",
        "apk": "application/vnd.android.package-archive",
        "pcap": "application/vnd.tcpdump.pcap",
    }
    return fallback.get(ext, "application/octet-stream")


def _score_to_level(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "CLEAN"


def _max_level(a: str, b: str) -> str:
    """Return the higher of two threat levels."""
    return a if _LEVEL_RANK.get(a, 0) >= _LEVEL_RANK.get(b, 0) else b


def _build_behaviors(pe: Optional[PEResult], yara: Optional[YARAScanResult],
                     iocs: Optional[ExtractedIOCs]) -> list[dict]:
    """Generate human-readable behavior summary for investigators."""
    behaviors = []

    if pe:
        if pe.packer_detected:
            behaviors.append({
                "severity": "HIGH",
                "title": f"Packer Detected: {pe.packer_detected}",
                "description": f"Binary is packed with {pe.packer_detected}. True payload is encrypted/compressed. Runtime unpacking required to analyze actual code.",
                "mitre": "T1027.002",
                "source": "static",
            })
        for s in pe.sections:
            if s.suspicious and s.entropy > 7.0:
                behaviors.append({
                    "severity": "HIGH",
                    "title": f"High-Entropy Section: {s.name} (entropy {s.entropy})",
                    "description": f"Section '{s.name}' has entropy {s.entropy} — strongly suggests encrypted or compressed payload.",
                    "mitre": "T1027",
                    "source": "static",
                })
            if s.suspicious and "RWX" in s.permissions:
                behaviors.append({
                    "severity": "HIGH",
                    "title": f"RWX Memory Section: {s.name}",
                    "description": f"Section '{s.name}' is writable AND executable — classic code injection staging area.",
                    "mitre": "T1055",
                    "source": "static",
                })
        if pe.total_suspicious_imports >= 5:
            sus_list = []
            for imp in pe.imports:
                sus_list.extend(imp.suspicious_funcs)
            behaviors.append({
                "severity": "HIGH",
                "title": f"Suspicious Win32 API Usage ({pe.total_suspicious_imports} functions)",
                "description": f"High-risk API functions detected: {', '.join(sus_list[:8])}. Consistent with code injection, credential access, or evasion.",
                "mitre": "T1055",
                "source": "static",
            })
        if pe.overlay_detected and pe.overlay_entropy and pe.overlay_entropy > 7.0:
            behaviors.append({
                "severity": "HIGH",
                "title": "Encrypted Overlay Data",
                "description": f"High-entropy data ({pe.overlay_entropy}) appended after PE structure. May contain embedded payload, config, or second stage.",
                "mitre": "T1027",
                "source": "static",
            })
        if pe.compile_time_suspicious:
            behaviors.append({
                "severity": "MEDIUM",
                "title": "Suspicious Compile Timestamp",
                "description": f"Compile time '{pe.compile_time}' appears forged or invalid. Common evasion technique.",
                "mitre": "T1027",
                "source": "static",
            })
        # Heuristic API combos
        if pe.has_injection_triad:
            behaviors.append({
                "severity": "CRITICAL",
                "title": "Process Injection API Triad Detected",
                "description": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread all present — textbook process injection capability.",
                "mitre": "T1055",
                "source": "static",
            })
        if pe.has_nt_evasion_apis:
            behaviors.append({
                "severity": "HIGH",
                "title": "NT/Zw Low-Level Syscall Wrappers (EDR Evasion)",
                "description": "NtAllocateVirtualMemory / ZwWriteVirtualMemory or similar low-level API wrappers imported. Common EDR bypass technique.",
                "mitre": "T1562.001",
                "source": "static",
            })
        if pe.has_network_apis and pe.has_crypto_apis and pe.has_file_enum_apis:
            behaviors.append({
                "severity": "HIGH",
                "title": "Ransomware API Combo (Networking + Crypto + File Enum)",
                "description": "Simultaneous presence of network, crypto, and file enumeration APIs — highly consistent with ransomware functionality even without YARA match.",
                "mitre": "T1486",
                "source": "static",
            })
        if pe.dynamic_import_resolution:
            behaviors.append({
                "severity": "HIGH",
                "title": "Dynamic Import Resolution (Evasion Technique)",
                "description": "Binary imports only LoadLibrary/GetProcAddress or has no imports — resolving all API calls at runtime to evade import-table scanning.",
                "mitre": "T1027.011",
                "source": "static",
            })

    if yara:
        for match in yara.matches:
            behaviors.append({
                "severity": match.severity,
                "title": f"YARA: {match.rule_name}",
                "description": match.description or f"Matched YARA rule for {match.family} malware family.",
                "mitre": ", ".join(match.mitre_ids) if match.mitre_ids else "",
                "source": "static",
            })

    if iocs:
        if iocs.domains:
            behaviors.append({
                "severity": "HIGH",
                "title": f"Suspicious Network Domains ({len(iocs.domains)})",
                "description": f"Embedded domains detected: {', '.join(iocs.domains[:3])}. Likely C2 or payload delivery infrastructure.",
                "mitre": "T1071.001",
                "source": "static",
            })
        if iocs.crypto_wallets:
            behaviors.append({
                "severity": "HIGH",
                "title": f"Cryptocurrency Wallet Addresses ({len(iocs.crypto_wallets)})",
                "description": "Hardcoded crypto wallet addresses found. Consistent with ransomware payment collection.",
                "mitre": "T1486",
                "source": "static",
            })
        if iocs.registry_keys:
            behaviors.append({
                "severity": "MEDIUM",
                "title": f"Registry Key References ({len(iocs.registry_keys)})",
                "description": f"Embedded registry paths: {iocs.registry_keys[0][:80]}... — possible persistence mechanism.",
                "mitre": "T1547.001",
                "source": "static",
            })

    # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return sorted(behaviors, key=lambda b: -rank.get(b["severity"], 0))


def _compute_static_score(ext: str, report: "AnalysisReport") -> tuple[int, list[dict]]:
    """
    Compute the static analysis risk score with full breakdown tracking.
    Returns (score, score_breakdown_list).
    """
    breakdown: list[dict] = []

    def add(label: str, points: int, source: str = "static") -> int:
        """Add points and record the breakdown entry."""
        breakdown.append({"label": label, "points": points, "source": source})
        return points

    score = 0

    # ── Base score from file type ─────────────────────────────────
    base = _EXT_BASE_RISK.get(ext, 8)
    score += add(f"File type ({ext.upper()})", base)

    # ── YARA matches ──────────────────────────────────────────────
    if report.yara:
        for match in report.yara.matches:
            pts = _SEVERITY_SCORE.get(match.severity, 0)
            if pts:
                score += add(f"YARA: {match.rule_name}", pts)

    # ── PE anomalies + heuristic scoring ─────────────────────────
    if report.pe_info:
        pe = report.pe_info

        # Packer section names — hard +20, minimum MEDIUM enforced later
        if pe.packer_detected:
            score += add(f"Packer detected: {pe.packer_detected}", 20)

        # High entropy sections — +30 EACH (was +5)
        for s in pe.sections:
            if s.entropy > 7.0:
                score += add(f"High-entropy section: {s.name} (entropy {s.entropy:.2f})", 30)

        # Suspicious imports
        if pe.total_suspicious_imports >= 5:
            score += add(f"Suspicious API functions ({pe.total_suspicious_imports})", 15)
        elif pe.total_suspicious_imports >= 2:
            score += add(f"Suspicious API functions ({pe.total_suspicious_imports})", 8)

        # Overlay
        if pe.overlay_detected:
            score += add("Encrypted overlay data", 8)

        # Forged timestamp
        if pe.compile_time_suspicious:
            score += add("Forged/suspicious compile timestamp", 10)

        # Heuristic API combos
        if pe.has_injection_triad:
            score += add("Process injection triad (VirtualAllocEx+WriteProcessMemory+CreateRemoteThread)", 25)

        if pe.has_nt_evasion_apis:
            score += add("NT/Zw low-level syscall wrappers (EDR evasion)", 15)

        if pe.has_network_apis and pe.has_crypto_apis and pe.has_file_enum_apis:
            score += add("Ransomware API combo (network + crypto + file enumeration)", 20)

        if pe.dynamic_import_resolution:
            score += add("Dynamic import resolution (LoadLibrary/GetProcAddress only)", 25)
        elif len(report.pe_info.imports) == 1:
            score += add("Single DLL import (possible dynamic resolution)", 10)

    # ── VirusTotal ────────────────────────────────────────────────
    if report.vt_result:
        if report.vt_result.found:
            if report.vt_result.malicious_engines >= 10:
                score += add(f"VirusTotal: {report.vt_result.malicious_engines} engines malicious", 30)
            elif report.vt_result.malicious_engines >= 3:
                score += add(f"VirusTotal: {report.vt_result.malicious_engines} engines malicious", 15)
            elif report.vt_result.malicious_engines >= 1:
                score += add(f"VirusTotal: {report.vt_result.malicious_engines} engines malicious", 8)
        else:
            # Not found in VT = unknown sample (suspicious in forensic context)
            score += add("VT: UNKNOWN SAMPLE — not previously seen (zero-day risk)", 10)

    # ── IOC density ───────────────────────────────────────────────
    if report.iocs:
        if len(report.iocs.domains) > 3:
            score += add(f"High C2 domain density ({len(report.iocs.domains)} domains)", 12)
        if len(report.iocs.crypto_wallets) > 0:
            score += add(f"Crypto wallet addresses ({len(report.iocs.crypto_wallets)})", 15)

    return min(score, 100), breakdown


def run_analysis(
    file_path: Path,
    yara_scanner: Optional[YARAScanner] = None,
    vt_client: Optional[VirusTotalClient] = None,
    abuseipdb_client: Optional[AbuseIPDBClient] = None,
    enable_vt: bool = True,
    enable_abuseipdb: bool = True,
    enable_dynamic: bool = False,
) -> AnalysisReport:
    """
    Run full analysis pipeline on a submitted file.

    Pipeline:
    1.  Compute cryptographic hashes
    2.  Detect MIME type
    3.  Parse PE headers (if applicable)
    4.  Run YARA scanner
    5.  Extract IOCs
    6.  Map to MITRE ATT&CK
    7.  Query VirusTotal (if API key available)
    8.  Query AbuseIPDB for extracted IPs (if API key available)
    9.  Build behavior summary
    10. Calculate composite risk score (with full breakdown)
    11. Apply static minimum floor rules
    12. Dynamic sandbox execution (if enable_dynamic=True)
    13. Weighted score merge + verdict reconciliation
    """
    report = AnalysisReport(
        filename=file_path.name,
        analysis_start=time.time(),
    )

    # ── 1. Hashes ──────────────────────────────────────────────
    try:
        logger.info(f"Computing hashes for {file_path.name}")
        report.hashes = compute_hashes(file_path)
        report.file_size = report.hashes.file_size
    except Exception as e:
        logger.error(f"Hash computation failed: {e}")

    # ── 2. MIME type ───────────────────────────────────────────
    ext = file_path.suffix.lower().lstrip(".")
    report.file_type = ext.upper()
    report.mime_type = _detect_mime(file_path)

    # ── 3. PE parsing (only for executables) ───────────────────
    pe_types = {"exe", "dll", "msi", "scr", "pif", "cpl", "sys", "drv"}
    if ext in pe_types:
        try:
            logger.info(f"Parsing PE structure: {file_path.name}")
            report.pe_info = parse_pe(file_path)
        except Exception as e:
            logger.error(f"PE parse failed: {e}")

    # ── 4. YARA scanning ───────────────────────────────────────
    if yara_scanner:
        try:
            logger.info(f"Running YARA scan: {file_path.name}")
            report.yara = yara_scanner.scan_file(file_path)
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

    # ── 5. IOC extraction ──────────────────────────────────────
    try:
        logger.info(f"Extracting IOCs from: {file_path.name}")
        report.iocs = extract_iocs(file_path)
    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")

    # ── 6. MITRE ATT&CK mapping ────────────────────────────────
    try:
        yara_families = []
        if report.yara:
            yara_families = list({m.family for m in report.yara.matches})

        suspicious_imports = []
        if report.pe_info:
            for imp in report.pe_info.imports:
                suspicious_imports.extend(imp.suspicious_funcs)

        pe_anomalies = report.pe_info.anomalies if report.pe_info else []
        report.mitre = map_to_attack(yara_families, suspicious_imports, pe_anomalies)
    except Exception as e:
        logger.error(f"MITRE mapping failed: {e}")

    # ── 7. VirusTotal lookup ───────────────────────────────────
    if enable_vt and vt_client and report.hashes:
        try:
            logger.info(f"Querying VirusTotal for {report.hashes.sha256[:16]}...")
            report.vt_result = vt_client.lookup_hash(report.hashes.sha256)
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")

    # ── 8. AbuseIPDB lookup (up to 15 IPs — expanded from 5) ──
    if enable_abuseipdb and abuseipdb_client and report.iocs:
        for ip in report.iocs.ips[:15]:
            try:
                result = abuseipdb_client.check_ip(ip)
                report.abuseipdb_results.append(result)
            except Exception as e:
                logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")

    # ── 8.1. IP Geolocation (free — no API key, up to 30 IPs) ─
    if report.iocs and report.iocs.ips:
        try:
            logger.info(f"Geolocating {len(report.iocs.ips[:30])} IPs via ip-api.com...")
            geo_results = geolocate_ips(report.iocs.ips[:30])
            report.ip_geo_results = {ip: geo.to_dict() for ip, geo in geo_results.items()}

            # Add HIGH C2 risk behavior for datacenter-hosted IPs
            dc_ips = [ip for ip, geo in geo_results.items() if geo.is_datacenter]
            if dc_ips:
                report.behaviors.insert(0, {
                    "severity": "HIGH",
                    "title": f"C2 Infrastructure Detected: {len(dc_ips)} Datacenter-Hosted IP(s)",
                    "description": (
                        f"IP addresses hosted in commercial datacenters detected: {', '.join(dc_ips[:5])}. "
                        "Attackers use cloud/datacenter IPs for C2 servers as they are fast, cheap, and "
                        "easy to abandon. This is a strong indicator of command-and-control infrastructure."
                    ),
                    "mitre": "T1583.003",
                    "source": "static",
                })

            # Add MEDIUM risk for proxy/VPN IPs
            proxy_ips = [ip for ip, geo in geo_results.items() if geo.is_proxy and not geo.is_datacenter]
            if proxy_ips:
                report.behaviors.insert(1, {
                    "severity": "MEDIUM",
                    "title": f"VPN/Proxy IPs Detected ({len(proxy_ips)} addresses)",
                    "description": (
                        f"Proxy or VPN IPs found embedded: {', '.join(proxy_ips[:3])}. "
                        "Malware uses proxies and VPNs to hide C2 traffic and attacker identity."
                    ),
                    "mitre": "T1090",
                    "source": "static",
                })

            logger.info(f"Geo: {len(geo_results)} IPs resolved, {len(dc_ips)} datacenter")
        except Exception as e:
            logger.error(f"IP geolocation failed: {e}")

    # ── 8.2. Domain C2 Intelligence (heuristic, no API needed) ─
    if report.iocs:
        try:
            ddns_set = set(report.iocs.ddns_domains or [])
            all_domains = list(set((report.iocs.domains or []) + list(ddns_set)))
            domain_intel = []
            for domain in all_domains[:50]:  # cap at 50
                is_ddns = domain in ddns_set
                intel = classify_domain_risk(domain, is_ddns=is_ddns)
                domain_intel.append(intel)

            # Sort: HIGH risk first
            risk_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
            domain_intel.sort(key=lambda x: -risk_rank.get(x.get("risk_level", "CLEAN"), 0))
            report.domain_intel = domain_intel

            # Add behavior for high-risk domains
            high_risk_domains = [d for d in domain_intel if d.get("risk_level") == "HIGH"]
            if high_risk_domains:
                report.behaviors.insert(0, {
                    "severity": "HIGH",
                    "title": f"High-Risk C2 Domains: {len(high_risk_domains)} Detected",
                    "description": (
                        f"Domains with high C2 risk score found: "
                        f"{', '.join(d['domain'] for d in high_risk_domains[:3])}. "
                        f"Risk factors: {'; '.join(high_risk_domains[0].get('reasons', [])[:2])}."
                    ),
                    "mitre": "T1071.001",
                    "source": "static",
                })

            logger.info(f"Domain intel: {len(domain_intel)} domains scored, {len(high_risk_domains)} HIGH risk")
        except Exception as e:
            logger.error(f"Domain C2 scoring failed: {e}")

    # ── 8.3. VirusTotal Domain Batch Lookup (top HIGH-risk domains) ─
    if enable_vt and vt_client and report.domain_intel:
        try:
            # Pick top 3 HIGH-risk domains not already on the allowlist
            top_domains = [
                d["domain"] for d in report.domain_intel
                if d.get("risk_level") in ("HIGH", "MEDIUM")
            ][:3]

            if top_domains:
                logger.info(f"VT domain lookup for {len(top_domains)} domain(s): {top_domains}")
                vt_domain_results = vt_client.lookup_domain_batch(top_domains, max_domains=3)
                report.vt_domain_results = vt_domain_results

                # Add CRITICAL behavior if any domain comes back MALICIOUS
                malicious_domains = [
                    d for d, r in vt_domain_results.items()
                    if r.get("verdict") == "MALICIOUS"
                ]
                if malicious_domains:
                    report.behaviors.insert(0, {
                        "severity": "CRITICAL",
                        "title": f"VirusTotal: {len(malicious_domains)} Domain(s) Confirmed MALICIOUS",
                        "description": (
                            f"VirusTotal flagged the following domains as malicious: "
                            f"{', '.join(malicious_domains[:3])}. "
                            "These are active threat infrastructure confirmed by multiple AV engines."
                        ),
                        "mitre": "T1071.001",
                        "source": "static",
                    })
        except Exception as e:
            logger.error(f"VT domain batch lookup failed: {e}")

    # ── 8.5. OTX + MalwareBazaar lookups ──────────────────────
    try:
        from app.core.intel.otx_bazaar import malwarebazaar_lookup, otx_lookup_hash
        import asyncio

        sha256 = report.hashes.sha256 if report.hashes else ""
        if sha256:
            # MalwareBazaar — no key needed, very fast
            loop = asyncio.new_event_loop()
            mb_result = loop.run_until_complete(malwarebazaar_lookup(sha256))
            loop.close()

            if mb_result and mb_result.found:
                report.malwarebazaar = {
                    "found": True,
                    "signature": mb_result.signature,
                    "file_type": mb_result.file_type,
                    "tags": mb_result.tags,
                    "reporter": mb_result.reporter,
                    "first_seen": mb_result.first_seen,
                    "last_seen": mb_result.last_seen,
                    "vendor_intel": mb_result.vendor_intel,
                    "verdict": "MALICIOUS",
                }
                logger.info(f"MalwareBazaar: {sha256[:8]}... found — {mb_result.signature}")
            else:
                report.malwarebazaar = {"found": False, "verdict": "UNKNOWN"}

            # OTX — only if key set
            if settings.OTX_API_KEY and settings.OTX_API_KEY != "your_otx_key_here":
                loop2 = asyncio.new_event_loop()
                otx_result = loop2.run_until_complete(otx_lookup_hash(sha256))
                loop2.close()
                if otx_result:
                    report.otx = {
                        "found": otx_result.pulse_count > 0,
                        "pulse_count": otx_result.pulse_count,
                        "verdict": otx_result.verdict,
                        "tags": otx_result.tags,
                        "malware_families": otx_result.malware_families,
                        "pulses": otx_result.pulses[:3],
                    }
                    # OTX floor rules
                    if otx_result.pulse_count >= 5 and _LEVEL_RANK.get(report.static_threat_level, 0) < _LEVEL_RANK["HIGH"]:
                        breakdown.append({"label": f"OTX: {otx_result.pulse_count} intelligence pulses — HIGH floor", "points": 0, "source": "static"})
            else:
                report.otx = None

    except Exception as e:
        logger.warning(f"OTX/MalwareBazaar lookup failed: {e}")

    # ── 9. Build behavior summary ──────────────────────────────
    report.behaviors = _build_behaviors(report.pe_info, report.yara, report.iocs)

    # ── 10. Static risk score (with full breakdown) ────────────
    static_score, breakdown = _compute_static_score(ext, report)
    report.score_breakdown = breakdown

    # ── 11. Static minimum floor rules ────────────────────────
    static_level = _score_to_level(static_score)

    # EXE types: never show CLEAN
    if ext in _EXE_TYPES and _LEVEL_RANK.get(static_level, 0) < _LEVEL_RANK["LOW"]:
        static_level = "LOW"
        static_score = max(static_score, 20)
        breakdown.append({"label": "EXE minimum floor (never CLEAN)", "points": 0, "source": "static"})

    # Packed without digital signature → minimum MEDIUM
    if report.pe_info and report.pe_info.force_minimum_medium:
        if _LEVEL_RANK.get(static_level, 0) < _LEVEL_RANK["MEDIUM"]:
            static_level = "MEDIUM"
            static_score = max(static_score, 40)
            breakdown.append({"label": "Packer detected — minimum MEDIUM floor", "points": 0, "source": "static"})

    # VT ≥ 3 → minimum HIGH
    if report.vt_result and report.vt_result.found:
        if report.vt_result.malicious_engines >= 10:
            if _LEVEL_RANK.get(static_level, 0) < _LEVEL_RANK["CRITICAL"]:
                static_level = "CRITICAL"
                static_score = max(static_score, 80)
                breakdown.append({"label": "VT ≥10 engines — minimum CRITICAL floor", "points": 0, "source": "static"})
        elif report.vt_result.malicious_engines >= 3:
            if _LEVEL_RANK.get(static_level, 0) < _LEVEL_RANK["HIGH"]:
                static_level = "HIGH"
                static_score = max(static_score, 60)
                breakdown.append({"label": "VT ≥3 engines — minimum HIGH floor", "points": 0, "source": "static"})

    # VT queried but hash NOT FOUND → flag as unknown sample
    if report.vt_result and not report.vt_result.found:
        if _LEVEL_RANK.get(static_level, 0) < _LEVEL_RANK["MEDIUM"]:
            static_level = "MEDIUM"
            static_score = max(static_score, 40)
            breakdown.append({"label": "Unknown sample (not in VT) — minimum MEDIUM floor", "points": 0, "source": "static"})
        # Add a behavior flag
        report.behaviors.insert(0, {
            "severity": "MEDIUM",
            "title": "⚠ UNKNOWN SAMPLE — Not Previously Seen in VirusTotal",
            "description": "This file hash was not found in the VirusTotal database. In a forensic context, an unknown file is SUSPICIOUS — not clean. It may be a new/modified malware variant or a zero-day sample.",
            "mitre": "",
            "source": "static",
        })

    report.static_score = min(static_score, 100)
    report.static_threat_level = static_level
    report.risk_score = report.static_score
    report.threat_level = report.static_threat_level

    # ── 12. Dynamic sandbox ────────────────────────────────────
    if enable_dynamic:
        try:
            logger.info(f"Running dynamic sandbox for {file_path.name}")
            dyn = run_dynamic_analysis(file_path, report)
            report.dynamic_result = dyn
            report.analysis_depth = "static+dynamic"

            # ── Weighted score merge: Static×0.4 + Dynamic×0.6 ──────────
            dynamic_score = dyn.dynamic_score if dyn.dynamic_score > 0 else (
                min(45 + dyn.risk_delta, 100)  # fallback: base + delta
            )
            merged_score = int(report.static_score * 0.4 + dynamic_score * 0.6)
            merged_score = min(merged_score, 100)

            breakdown.append({
                "label": f"Dynamic sandbox score (×0.6 weight): {dynamic_score}/100",
                "points": dynamic_score,
                "source": "dynamic",
            })
            breakdown.append({
                "label": f"Static score reweighted (×0.4): {report.static_score}/100",
                "points": report.static_score,
                "source": "static",
            })

            # Final verdict = MAX of the two levels
            dynamic_level = (
                "CRITICAL" if dyn.sandbox_verdict == "MALICIOUS" and dynamic_score >= 80 else
                "HIGH"     if dyn.sandbox_verdict == "MALICIOUS" else
                "MEDIUM"   if dyn.sandbox_verdict == "SUSPICIOUS" else
                "LOW"
            )
            final_level = _max_level(report.static_threat_level, dynamic_level)

            # ── Hard floor rules from dynamic observations ───────────────
            if dyn.observed_file_encryption:
                final_level = "CRITICAL"
                merged_score = max(merged_score, 80)
                breakdown.append({"label": "DYNAMIC: File encryption observed — CRITICAL floor", "points": 0, "source": "dynamic"})

            if dyn.observed_process_injection:
                if _LEVEL_RANK.get(final_level, 0) < _LEVEL_RANK["HIGH"]:
                    final_level = "HIGH"
                    merged_score = max(merged_score, 60)
                breakdown.append({"label": "DYNAMIC: Process injection observed — HIGH floor", "points": 0, "source": "dynamic"})

            if dyn.observed_persistence:
                if _LEVEL_RANK.get(final_level, 0) < _LEVEL_RANK["HIGH"]:
                    final_level = "HIGH"
                    merged_score = max(merged_score, 60)
                breakdown.append({"label": "DYNAMIC: Persistence mechanism observed — HIGH floor", "points": 0, "source": "dynamic"})

            if dyn.observed_network_connection:
                if _LEVEL_RANK.get(final_level, 0) < _LEVEL_RANK["MEDIUM"]:
                    final_level = "MEDIUM"
                    merged_score = max(merged_score, 40)
                breakdown.append({"label": "DYNAMIC: Network connection attempted — MEDIUM floor", "points": 0, "source": "dynamic"})

            report.risk_score = min(merged_score, 100)
            report.threat_level = final_level

            # ── VERDICT CONFLICT detection ────────────────────────────────
            static_rank = _LEVEL_RANK.get(report.static_threat_level, 0)
            dynamic_rank = _LEVEL_RANK.get(dynamic_level, 0)
            if abs(static_rank - dynamic_rank) >= 2:
                report.verdict_conflict = True
                higher = "dynamic" if dynamic_rank > static_rank else "static"
                report.verdict_conflict_explanation = (
                    f"Static analysis verdict: {report.static_threat_level} (score {report.static_score}/100). "
                    f"Dynamic sandbox verdict: {dynamic_level} (score {dynamic_score}/100). "
                    f"Final verdict: {final_level} — {higher} analysis takes precedence. "
                    f"Static analysis may have missed indicators due to runtime packing or obfuscation. "
                    f"Dynamic execution revealed additional malicious behavior. "
                    f"Final verdict reflects observed runtime activity."
                )
                logger.warning(
                    f"VERDICT CONFLICT for {file_path.name}: "
                    f"static={report.static_threat_level} dynamic={dynamic_level} final={final_level}"
                )

            # ── Merge dynamic MITRE techniques ────────────────────────────
            existing_ids = {t.technique_id for t in report.mitre}
            for tech in dyn.mitre_techniques:
                if tech["id"] not in existing_ids:
                    from app.core.mitre_mapper import ATTACKTechnique
                    report.mitre.append(ATTACKTechnique(
                        technique_id=tech["id"],
                        name=tech["name"],
                        tactic=tech["tactic"],
                        confidence="CRITICAL",
                        source=tech["source"],
                    ))
                    existing_ids.add(tech["id"])

            # ── Merge dynamic network IOCs ────────────────────────────────
            if report.iocs and dyn.network_iocs:
                for net_ioc in dyn.network_iocs:
                    val = net_ioc.get("value", "")
                    if net_ioc.get("type") == "domain" and val not in report.iocs.domains:
                        report.iocs.domains.append(val)
                    elif net_ioc.get("type") == "ip" and val not in report.iocs.ips:
                        report.iocs.ips.append(val)

            # ── Add dynamic behaviors with source label ───────────────────
            for ev in dyn.events:
                if ev.severity in ("CRITICAL", "HIGH"):
                    report.behaviors.insert(0, {
                        "severity": ev.severity,
                        "title": f"[DYNAMIC] {ev.description[:80]}",
                        "description": f"Observed during sandbox execution at {ev.timestamp_fmt}: {ev.description}. Resource: {ev.resource}",
                        "mitre": ev.mitre_id,
                        "source": "dynamic",
                    })

        except Exception as e:
            logger.error(f"Dynamic sandbox failed for {file_path.name}: {e}")
            report.analysis_depth = "static"

    report.finalize()
    logger.info(
        f"Analysis complete: {file_path.name} | "
        f"Score={report.risk_score} | Level={report.threat_level} | "
        f"Depth={report.analysis_depth} | Conflict={report.verdict_conflict} | "
        f"{report.analysis_duration_ms}ms"
    )
    return report
