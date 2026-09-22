"""
CyberForge — MITRE ATT&CK Mapper
Maps analysis findings (YARA matches, PE imports, behaviors) to MITRE ATT&CK techniques.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ATTACKTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: str      # CRITICAL / HIGH / MEDIUM / LOW
    source: str          # what triggered this mapping
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "id":         self.technique_id,
            "name":       self.name,
            "tactic":     self.tactic,
            "confidence": self.confidence,
            "source":     self.source,
            "url":        f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}",
        }


# ── API → ATT&CK mappings ───────────────────────────────────────
API_TO_ATTACK = {
    # Process injection
    "VirtualAllocEx":           ("T1055",     "Process Injection",                "Defense Evasion",  "HIGH"),
    "WriteProcessMemory":       ("T1055",     "Process Injection",                "Defense Evasion",  "HIGH"),
    "CreateRemoteThread":       ("T1055.003", "Thread Execution Hijacking",       "Defense Evasion",  "HIGH"),
    "NtCreateThreadEx":         ("T1055",     "Process Injection",                "Defense Evasion",  "HIGH"),
    "ZwUnmapViewOfSection":     ("T1055.012", "Process Hollowing",                "Defense Evasion",  "CRITICAL"),
    "NtUnmapViewOfSection":     ("T1055.012", "Process Hollowing",                "Defense Evasion",  "CRITICAL"),
    "QueueUserAPC":             ("T1055.004", "Asynchronous Procedure Call",      "Defense Evasion",  "HIGH"),
    "NtQueueApcThread":         ("T1055.004", "Asynchronous Procedure Call",      "Defense Evasion",  "HIGH"),
    "SetThreadContext":         ("T1055.003", "Thread Execution Hijacking",       "Defense Evasion",  "HIGH"),
    "GetThreadContext":         ("T1055",     "Process Injection",                "Defense Evasion",  "MEDIUM"),

    # Persistence - Registry
    "RegSetValueExA":           ("T1547.001", "Registry Run Keys / Startup Folder","Persistence",     "HIGH"),
    "RegSetValueExW":           ("T1547.001", "Registry Run Keys / Startup Folder","Persistence",     "HIGH"),
    "RegCreateKeyExA":          ("T1547.001", "Registry Run Keys / Startup Folder","Persistence",     "MEDIUM"),
    "RegCreateKeyExW":          ("T1547.001", "Registry Run Keys / Startup Folder","Persistence",     "MEDIUM"),

    # Persistence - Services
    "CreateServiceA":           ("T1543.003", "Windows Service",                  "Persistence",      "HIGH"),
    "CreateServiceW":           ("T1543.003", "Windows Service",                  "Persistence",      "HIGH"),
    "OpenSCManagerA":           ("T1543.003", "Windows Service",                  "Persistence",      "MEDIUM"),
    "StartServiceA":            ("T1543.003", "Windows Service",                  "Persistence",      "MEDIUM"),

    # Credential access
    "CryptAcquireContextA":     ("T1552.001", "Credentials In Files",             "Credential Access","MEDIUM"),
    "CryptEncrypt":             ("T1486",     "Data Encrypted for Impact",        "Impact",           "HIGH"),
    "CryptDecrypt":             ("T1140",     "Deobfuscate/Decode Files",         "Defense Evasion",  "LOW"),
    "OpenProcessToken":         ("T1134",     "Access Token Manipulation",        "Defense Evasion",  "MEDIUM"),
    "AdjustTokenPrivileges":    ("T1134.001", "Token Impersonation/Theft",        "Defense Evasion",  "HIGH"),

    # Discovery
    "GetSystemInfo":            ("T1082",     "System Information Discovery",     "Discovery",        "LOW"),
    "GetComputerNameA":         ("T1082",     "System Information Discovery",     "Discovery",        "LOW"),
    "EnumProcesses":            ("T1057",     "Process Discovery",                "Discovery",        "MEDIUM"),
    "CreateToolhelp32Snapshot": ("T1057",     "Process Discovery",                "Discovery",        "MEDIUM"),
    "FindFirstFileW":           ("T1083",     "File and Directory Discovery",     "Discovery",        "LOW"),
    "NetShareEnum":             ("T1135",     "Network Share Discovery",          "Discovery",        "MEDIUM"),

    # Network / C2
    "WSAStartup":               ("T1071.001", "Web Protocols",                    "Command and Control","MEDIUM"),
    "connect":                  ("T1071.001", "Web Protocols",                    "Command and Control","MEDIUM"),
    "InternetOpenA":            ("T1071.001", "Web Protocols",                    "Command and Control","HIGH"),
    "HttpSendRequestA":         ("T1071.001", "Web Protocols",                    "Command and Control","HIGH"),
    "URLDownloadToFileA":       ("T1105",     "Ingress Tool Transfer",            "Command and Control","HIGH"),

    # Evasion
    "IsDebuggerPresent":        ("T1622",     "Debugger Evasion",                 "Defense Evasion",  "MEDIUM"),
    "CheckRemoteDebuggerPresent":("T1622",    "Debugger Evasion",                 "Defense Evasion",  "MEDIUM"),
    "NtQueryInformationProcess":("T1622",     "Debugger Evasion",                 "Defense Evasion",  "HIGH"),
    "LoadLibraryA":             ("T1574.001", "DLL Search Order Hijacking",       "Defense Evasion",  "LOW"),

    # Impact
    "DeleteFileA":              ("T1485",     "Data Destruction",                 "Impact",           "MEDIUM"),
    "MoveFileExA":              ("T1036",     "Masquerading",                     "Defense Evasion",  "LOW"),
}

# ── YARA family → ATT&CK mappings ─────────────────────────────
FAMILY_TO_ATTACK = {
    "Ransomware": [
        ("T1486",     "Data Encrypted for Impact",     "Impact",           "CRITICAL"),
        ("T1490",     "Inhibit System Recovery",       "Impact",           "CRITICAL"),
        ("T1489",     "Service Stop",                  "Impact",           "HIGH"),
        ("T1083",     "File and Directory Discovery",  "Discovery",        "MEDIUM"),
    ],
    "Injector": [
        ("T1055",     "Process Injection",             "Defense Evasion",  "CRITICAL"),
        ("T1055.012", "Process Hollowing",             "Defense Evasion",  "HIGH"),
    ],
    "Infostealer": [
        ("T1555.003", "Credentials from Web Browsers","Credential Access", "HIGH"),
        ("T1005",     "Data from Local System",        "Collection",        "HIGH"),
        ("T1056.001", "Keylogging",                    "Collection",        "MEDIUM"),
    ],
    "CredentialDump": [
        ("T1003.001", "LSASS Memory",                  "Credential Access", "CRITICAL"),
        ("T1134",     "Access Token Manipulation",     "Defense Evasion",  "HIGH"),
    ],
    "Persistence": [
        ("T1547.001", "Registry Run Keys",             "Persistence",       "HIGH"),
        ("T1053.005", "Scheduled Task",                "Persistence",       "MEDIUM"),
    ],
    "Packed": [
        ("T1027.002", "Software Packing",              "Defense Evasion",   "MEDIUM"),
        ("T1140",     "Deobfuscate/Decode Files",      "Defense Evasion",   "LOW"),
    ],
    "Obfuscation": [
        ("T1027",     "Obfuscated Files or Information","Defense Evasion",  "MEDIUM"),
        ("T1059.001", "PowerShell",                    "Execution",         "HIGH"),
    ],
    "Downloader": [
        ("T1105",     "Ingress Tool Transfer",         "Command and Control","HIGH"),
        ("T1059.001", "PowerShell",                    "Execution",         "MEDIUM"),
    ],
    "C2": [
        ("T1071.001", "Web Protocols",                 "Command and Control","HIGH"),
        ("T1573",     "Encrypted Channel",             "Command and Control","MEDIUM"),
    ],
    "CobaltStrike": [
        ("T1071.001", "Web Protocols",                 "Command and Control","CRITICAL"),
        ("T1055",     "Process Injection",             "Defense Evasion",   "CRITICAL"),
        ("T1573",     "Encrypted Channel",             "Command and Control","HIGH"),
    ],
    "Keylogger": [
        ("T1056.001", "Keylogging",                    "Collection",        "HIGH"),
    ],
    "ClipboardStealer": [
        ("T1115",     "Clipboard Data",               "Collection",         "MEDIUM"),
    ],
    "CryptoStealer": [
        ("T1005",     "Data from Local System",        "Collection",        "HIGH"),
        ("T1552.001", "Credentials in Files",         "Credential Access",  "HIGH"),
    ],
    "Bootkit": [
        ("T1542.003", "Bootkit",                       "Persistence",       "CRITICAL"),
    ],
    "DLLInjection": [
        ("T1055.001", "Dynamic-link Library Injection","Defense Evasion",   "HIGH"),
    ],
}


def map_to_attack(
    yara_families: list[str],
    suspicious_imports: list[str],
    pe_anomalies: list[str],
) -> list[ATTACKTechnique]:
    """
    Given YARA-matched families, suspicious API imports, and PE anomalies,
    return a deduplicated list of MITRE ATT&CK techniques.
    """
    techniques: dict[str, ATTACKTechnique] = {}

    # From YARA families
    for family in yara_families:
        mappings = FAMILY_TO_ATTACK.get(family, [])
        for tid, name, tactic, conf in mappings:
            if tid not in techniques:
                techniques[tid] = ATTACKTechnique(
                    technique_id=tid, name=name, tactic=tactic,
                    confidence=conf, source=f"YARA:{family}"
                )

    # From suspicious imports
    for api in suspicious_imports:
        if api in API_TO_ATTACK:
            tid, name, tactic, conf = API_TO_ATTACK[api]
            if tid not in techniques:
                techniques[tid] = ATTACKTechnique(
                    technique_id=tid, name=name, tactic=tactic,
                    confidence=conf, source=f"Import:{api}"
                )

    # From PE anomalies
    for anomaly in pe_anomalies:
        if "RWX" in anomaly:
            tid = "T1055"
            if tid not in techniques:
                techniques[tid] = ATTACKTechnique(
                    technique_id=tid, name="Process Injection",
                    tactic="Defense Evasion", confidence="MEDIUM",
                    source="PE:RWX section"
                )
        if "packer" in anomaly.lower() or "packed" in anomaly.lower():
            tid = "T1027.002"
            if tid not in techniques:
                techniques[tid] = ATTACKTechnique(
                    technique_id=tid, name="Software Packing",
                    tactic="Defense Evasion", confidence="MEDIUM",
                    source="PE:Packer"
                )
        if "overlay" in anomaly.lower():
            tid = "T1027"
            if tid not in techniques:
                techniques[tid] = ATTACKTechnique(
                    technique_id=tid, name="Obfuscated Files or Information",
                    tactic="Defense Evasion", confidence="LOW",
                    source="PE:Overlay"
                )

    # Sort by confidence then tactic
    conf_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return sorted(
        techniques.values(),
        key=lambda t: (-conf_rank.get(t.confidence, 0), t.tactic)
    )
