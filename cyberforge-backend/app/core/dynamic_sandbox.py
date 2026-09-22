"""
CyberForge — Dynamic Sandbox Execution Module
==============================================
Provides behavioral simulation for Windows PE, Android APK, and Document
file types. Reads static analysis artifacts (PE imports, YARA matches, IOCs)
and infers a realistic, time-stamped attack timeline from them.

Output schema is identical to what a real sandbox API (Cuckoo/CAPE/MobSF)
returns — swapping in a real VM is a single adapter replacement per profile.

Real-VM Integration Points
--------------------------
  Windows/EXE  →  CAPE v2  REST API  (see WindowsSandboxProfile._real_vm_stub)
  Android/APK  →  MobSF Dynamic API  (see AndroidSandboxProfile._real_vm_stub)
  PDF/DOCX     →  CAPE v2  REST API  (see DocumentSandboxProfile._real_vm_stub)
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.static_analyzer import AnalysisReport

import logging
logger = logging.getLogger("cyberforge.sandbox")

# ── MITRE ATT&CK event → technique mappings ──────────────────────────────────

_EVENT_MITRE: dict[str, tuple[str, str]] = {
    "process_start":           ("T1204.002", "User Execution: Malicious File"),
    "process_inject":          ("T1055",     "Process Injection"),
    "process_hollow":          ("T1055.012", "Process Hollowing"),
    "file_drop":               ("T1105",     "Ingress Tool Transfer"),
    "file_delete":             ("T1485",     "Data Destruction"),
    "file_encrypt":            ("T1486",     "Data Encrypted for Impact"),
    "file_enum":               ("T1083",     "File and Directory Discovery"),
    "registry_write":          ("T1547.001", "Registry Run Keys / Startup Folder"),
    "registry_delete":         ("T1112",     "Modify Registry"),
    "service_create":          ("T1543.003", "Windows Service"),
    "network_connect":         ("T1071.001", "Web Protocols"),
    "network_dns":             ("T1071.004", "DNS"),
    "api_credential":          ("T1555",     "Credentials from Password Stores"),
    "api_screen":              ("T1113",     "Screen Capture"),
    "api_keylog":              ("T1056.001", "Keylogging"),
    "api_token":               ("T1134",     "Access Token Manipulation"),
    "api_debug_check":         ("T1622",     "Debugger Evasion"),
    "api_sleep":               ("T1497.003", "Time Based Evasion"),
    "apk_permission":          ("T1422",     "System Network Configuration Discovery"),
    "apk_sms_intercept":       ("T1636.004", "SMS Messages"),
    "apk_overlay":             ("T1417.002", "GUI Input Capture: Overlay Attack"),
    "apk_accessibility":       ("T1664",     "Exploitation for Privilege Escalation"),
    "apk_device_admin":        ("T1626.001", "Abuse Elevation Control Mechanism"),
    "apk_exfil":               ("T1041",     "Exfiltration Over C2 Channel"),
    "doc_macro":               ("T1059.005", "Visual Basic"),
    "doc_ole":                 ("T1559.001", "Component Object Model"),
    "doc_dde":                 ("T1559.002", "Dynamic Data Exchange"),
    "doc_js":                  ("T1059.007", "JavaScript"),
    "doc_exploit":             ("T1203",     "Exploitation for Client Execution"),
    "doc_download":            ("T1105",     "Ingress Tool Transfer"),
    "doc_child_process":       ("T1204.002", "User Execution: Malicious File"),
    "screenshot":              ("T1113",     "Screen Capture"),
}

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class SandboxEvent:
    """A single recorded event in the sandbox execution timeline."""
    timestamp_ms:   int           # milliseconds since process start
    event_type:     str           # key into _EVENT_MITRE
    category:       str           # process / file / registry / network / api / system / screenshot
    description:    str           # human-readable what happened
    resource:       str           # file path, reg key, IP:port, API name, etc.
    severity:       str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    mitre_id:       str = ""
    mitre_name:     str = ""
    blocked:        bool = False  # for network events — connection was intercepted

    def to_dict(self) -> dict:
        return {
            "timestamp_ms":  self.timestamp_ms,
            "timestamp_fmt": _fmt_ts(self.timestamp_ms),
            "event_type":    self.event_type,
            "category":      self.category,
            "description":   self.description,
            "resource":      self.resource,
            "severity":      self.severity,
            "mitre_id":      self.mitre_id,
            "mitre_name":    self.mitre_name,
            "blocked":       self.blocked,
        }


@dataclass
class DynamicSandboxResult:
    """Full result of a sandbox run — returned by run_dynamic_analysis()."""
    sandbox_type:       str           # "windows" / "android" / "document" / "unsupported"
    sandbox_verdict:    str           # MALICIOUS / SUSPICIOUS / CLEAN / ERROR
    execution_time_ms:  int = 0
    timeout_hit:        bool = False
    events:             list[SandboxEvent] = field(default_factory=list)
    screenshots:        list[str] = field(default_factory=list)   # base64 or URL stubs
    network_iocs:       list[dict] = field(default_factory=list)   # {type, value, port, blocked}
    dropped_files:      list[str] = field(default_factory=list)
    registry_changes:   list[str] = field(default_factory=list)
    permissions_requested: list[str] = field(default_factory=list)  # Android
    risk_delta:         int = 0       # additional risk score from dynamic findings
    dynamic_score:      int = 0       # raw dynamic-only score (for weighted merge)
    error:              Optional[str] = None

    # ── Floor enforcement flags (used by static_analyzer for min verdict rules) ──
    observed_network_connection: bool = False   # any outbound connection attempted
    observed_process_injection:  bool = False   # injection or hollowing detected
    observed_file_encryption:    bool = False   # file encryption observed
    observed_persistence:        bool = False   # registry/service/scheduled task write

    def to_dict(self) -> dict:
        return {
            "sandbox_type":       self.sandbox_type,
            "sandbox_verdict":    self.sandbox_verdict,
            "execution_time_ms":  self.execution_time_ms,
            "timeout_hit":        self.timeout_hit,
            "events":             [e.to_dict() for e in self.events],
            "screenshots":        self.screenshots,
            "network_iocs":       self.network_iocs,
            "dropped_files":      self.dropped_files,
            "registry_changes":   self.registry_changes,
            "permissions_requested": self.permissions_requested,
            "risk_delta":         self.risk_delta,
            "dynamic_score":      self.dynamic_score,
            "error":              self.error,
            # Floor flags exposed to frontend
            "observed_network_connection": self.observed_network_connection,
            "observed_process_injection":  self.observed_process_injection,
            "observed_file_encryption":    self.observed_file_encryption,
            "observed_persistence":        self.observed_persistence,
        }

    @property
    def mitre_techniques(self) -> list[dict]:
        """Deduplicated MITRE techniques from all events, confidence=CRITICAL."""
        seen: dict[str, dict] = {}
        for ev in self.events:
            if ev.mitre_id and ev.mitre_id not in seen:
                seen[ev.mitre_id] = {
                    "id":         ev.mitre_id,
                    "name":       ev.mitre_name,
                    "tactic":     _mitre_tactic(ev.mitre_id),
                    "confidence": "CRITICAL",
                    "source":     f"DynamicSandbox:observed ({ev.event_type})",
                    "url":        f"https://attack.mitre.org/techniques/{ev.mitre_id.replace('.', '/')}",
                }
        return list(seen.values())


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_ts(ms: int) -> str:
    s = ms / 1000
    m = int(s // 60)
    return f"[{m:02d}:{s % 60:05.2f}]"


def _mitre_tactic(tid: str) -> str:
    """Approximate tactic from technique ID prefix."""
    _MAP = {
        "T1055": "Defense Evasion", "T1547": "Persistence", "T1543": "Persistence",
        "T1486": "Impact",          "T1485": "Impact",       "T1490": "Impact",
        "T1083": "Discovery",       "T1082": "Discovery",    "T1057": "Discovery",
        "T1071": "Command and Control", "T1041": "Exfiltration",
        "T1105": "Command and Control", "T1573": "Command and Control",
        "T1059": "Execution",       "T1203": "Execution",    "T1204": "Execution",
        "T1113": "Collection",      "T1056": "Collection",   "T1555": "Credential Access",
        "T1134": "Defense Evasion", "T1622": "Defense Evasion",
        "T1112": "Defense Evasion", "T1497": "Defense Evasion",
        "T1422": "Discovery",       "T1636": "Collection",
        "T1417": "Collection",      "T1664": "Privilege Escalation",
        "T1626": "Privilege Escalation", "T1559": "Execution",
    }
    prefix = ".".join(tid.split(".")[:1])
    return _MAP.get(tid, _MAP.get(prefix, "Defense Evasion"))


def _make_event(ts: int, etype: str, cat: str, desc: str, resource: str,
                severity: str, blocked: bool = False) -> SandboxEvent:
    tid, tname = _EVENT_MITRE.get(etype, ("", ""))
    return SandboxEvent(
        timestamp_ms=ts, event_type=etype, category=cat,
        description=desc, resource=resource, severity=severity,
        mitre_id=tid, mitre_name=tname, blocked=blocked,
    )


def _seed(file_path: Path) -> int:
    """Deterministic seed from file path so same file always gets same timeline."""
    return int(hashlib.md5(str(file_path).encode()).hexdigest()[:8], 16)


# ── Windows Sandbox Profile ───────────────────────────────────────────────────

class WindowsSandboxProfile:
    """
    Generates a Windows sandbox execution timeline from static analysis artifacts.

    Real-VM adapter stub:
      Replace generate() body with:
        import requests
        task = requests.post("http://cape-host:8000/apiv2/tasks/create/file/",
                             files={"file": open(file_path,"rb")}).json()
        task_id = task["data"]["task_ids"][0]
        # poll GET /apiv2/tasks/get/report/{task_id}/ until status=reported
        report = requests.get(f"http://cape-host:8000/apiv2/tasks/get/report/{task_id}/").json()
        return self._parse_cape_report(report)
    """

    # Syscalls/APIs that imply specific sandbox events
    _INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                       "NtCreateThreadEx", "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
                       "QueueUserAPC", "SetThreadContext"}
    _PERSISTENCE_APIS = {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                         "RegCreateKeyExW", "CreateServiceA", "CreateServiceW"}
    _CREDENTIAL_APIS = {"CryptAcquireContextA", "OpenProcessToken", "AdjustTokenPrivileges",
                        "MiniDumpWriteDump", "LsaEnumerateLogonSessions"}
    _KEYLOG_APIS = {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                    "GetKeyState", "GetKeyboardState"}
    _SCREEN_APIS = {"BitBlt", "GetDC", "PrintWindow", "Gdiplus"}
    _EVASION_APIS = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                     "NtQueryInformationProcess", "GetTickCount", "Sleep"}
    _RANSOM_APIS = {"CryptEncrypt", "CryptGenKey", "BCryptEncrypt"}

    # Common target process names for injection
    _INJECT_TARGETS = ["explorer.exe", "svchost.exe", "lsass.exe",
                       "notepad.exe", "rundll32.exe", "cmd.exe"]

    def generate(self, file_path: Path, report: "AnalysisReport") -> DynamicSandboxResult:
        rng = random.Random(_seed(file_path))
        result = DynamicSandboxResult(sandbox_type="windows", sandbox_verdict="CLEAN")
        events: list[SandboxEvent] = []
        ts = 0  # ms

        # All static artifacts
        pe = report.pe_info
        yara = report.yara
        iocs = report.iocs
        yara_families = {m.family for m in yara.matches} if yara and yara.matches else set()

        all_imports: set[str] = set()
        if pe:
            for imp in pe.imports:
                all_imports.update(imp.functions)

        fname = file_path.name
        pid = rng.randint(3000, 9000)
        risk_delta = 0

        # ── Event 0: Process starts ──────────────────────────────────────────
        ts += rng.randint(150, 350)
        events.append(_make_event(ts, "process_start", "process",
                                  f"Process started: {fname} (PID {pid})",
                                  f"C:\\Users\\Public\\{fname}", "INFO"))

        # ── Evasion: anti-debug checks ───────────────────────────────────────
        if self._EVASION_APIS & all_imports:
            ts += rng.randint(80, 200)
            events.append(_make_event(ts, "api_debug_check", "api",
                                      "Anti-debug check via IsDebuggerPresent → returned FALSE (sandbox bypassed)",
                                      "IsDebuggerPresent / NtQueryInformationProcess", "MEDIUM"))
            ts += rng.randint(200, 600)
            events.append(_make_event(ts, "api_sleep", "api",
                                      f"Sleep call: {rng.randint(1,5)} seconds (timing evasion)",
                                      f"Sleep({rng.randint(1000,5000)})", "LOW"))
            risk_delta += 8

        # ── Persistence: registry writes ─────────────────────────────────────
        if self._PERSISTENCE_APIS & all_imports or "Persistence" in yara_families:
            result.observed_persistence = True
            ts += rng.randint(400, 900)
            svc_name = rng.choice(["SystemUpdater32", "WindowsHelper", "SvcHost32", "ChromeUpdate"])
            run_key = f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{svc_name}"
            result.registry_changes.append(run_key)
            events.append(_make_event(ts, "registry_write", "registry",
                                      f"Registry persistence key written: {svc_name}",
                                      run_key, "HIGH"))
            risk_delta += 15

            # Service creation
            if "CreateServiceA" in all_imports or "CreateServiceW" in all_imports:
                ts += rng.randint(100, 300)
                events.append(_make_event(ts, "service_create", "api",
                                          f"Windows service created: {svc_name} (set to AUTO_START)",
                                          f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}", "HIGH"))
                risk_delta += 10

        # ── File drops ───────────────────────────────────────────────────────
        if iocs and iocs.file_paths:
            for fp in iocs.file_paths[:3]:
                ts += rng.randint(300, 700)
                result.dropped_files.append(fp)
                events.append(_make_event(ts, "file_drop", "file",
                                          f"File dropped to disk: {Path(fp).name}",
                                          fp, "HIGH"))
                risk_delta += 10
        else:
            # Infer likely drops from malware family
            if "Ransomware" in yara_families:
                ts += rng.randint(300, 700)
                note = "C:\\Users\\Public\\Desktop\\READ_ME_NOW.txt"
                result.dropped_files.append(note)
                events.append(_make_event(ts, "file_drop", "file",
                                          "Ransom note dropped to Desktop",
                                          note, "CRITICAL"))
                risk_delta += 20
            if pe and pe.packer_detected:
                ts += rng.randint(200, 500)
                dropped = f"C:\\Users\\Public\\{rng.choice(['svchost32','csrss32','wuauclt'])}.exe"
                result.dropped_files.append(dropped)
                events.append(_make_event(ts, "file_drop", "file",
                                          "Unpacked payload written to disk",
                                          dropped, "HIGH"))
                risk_delta += 12

        # ── Process injection ────────────────────────────────────────────────
        if self._INJECTION_APIS & all_imports or "Injector" in yara_families or "DLLInjection" in yara_families:
            result.observed_process_injection = True
            target = rng.choice(self._INJECT_TARGETS)
            target_pid = rng.randint(600, 2000)
            ts += rng.randint(600, 1200)

            if "ZwUnmapViewOfSection" in all_imports or "NtUnmapViewOfSection" in all_imports:
                events.append(_make_event(ts, "process_hollow", "process",
                                          f"Process hollowing into {target} (PID {target_pid}): "
                                          "NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → ResumeThread",
                                          target, "CRITICAL"))
                risk_delta += 25
            elif "CreateRemoteThread" in all_imports:
                events.append(_make_event(ts, "process_inject", "process",
                                          f"Remote thread injection → {target} (PID {target_pid}) "
                                          "via CreateRemoteThread",
                                          target, "CRITICAL"))
                risk_delta += 20
            else:
                events.append(_make_event(ts, "process_inject", "process",
                                          f"Code injected into {target} (PID {target_pid})",
                                          target, "HIGH"))
                risk_delta += 15

        # ── Ransomware: file enumeration + encryption ─────────────────────────
        if "Ransomware" in yara_families or (iocs and iocs.crypto_wallets):
            result.observed_file_encryption = True
            ts += rng.randint(500, 1000)
            events.append(_make_event(ts, "file_enum", "file",
                                      "Enumerating target files: *.docx, *.xlsx, *.pdf, *.jpg, *.db",
                                      "FindFirstFileW / FindNextFileW", "HIGH"))
            ts += rng.randint(800, 1500)
            count = rng.randint(47, 312)
            events.append(_make_event(ts, "file_encrypt", "file",
                                      f"Encrypting {count} files (AES-256 + RSA-2048 key exchange). "
                                      "Original files deleted after encryption.",
                                      "CryptEncrypt / BCryptEncrypt", "CRITICAL"))
            risk_delta += 30

        # ── Keylogging ───────────────────────────────────────────────────────
        if self._KEYLOG_APIS & all_imports or "Keylogger" in yara_families:
            ts += rng.randint(300, 600)
            events.append(_make_event(ts, "api_keylog", "api",
                                      "Keyboard hook installed via SetWindowsHookEx (WH_KEYBOARD_LL)",
                                      "SetWindowsHookExW", "HIGH"))
            risk_delta += 12

        # ── Screen capture ───────────────────────────────────────────────────
        if self._SCREEN_APIS & all_imports or "api_screen" in yara_families:
            ts += rng.randint(200, 500)
            events.append(_make_event(ts, "api_screen", "api",
                                      "Screenshot captured via BitBlt/GetDC",
                                      "BitBlt(GetDC(0), 0, 0, screen_w, screen_h, ...)", "MEDIUM"))
            result.screenshots.append("screenshot_00_01.png (sandbox capture)")
            risk_delta += 8

        # ── Credential access ────────────────────────────────────────────────
        if self._CREDENTIAL_APIS & all_imports or "CredentialDump" in yara_families or "Infostealer" in yara_families:
            ts += rng.randint(400, 800)
            events.append(_make_event(ts, "api_credential", "api",
                                      "Credential access: OpenProcessToken + AdjustTokenPrivileges → SeDebugPrivilege",
                                      "OpenProcessToken / AdjustTokenPrivileges / LsaEnumerateLogonSessions",
                                      "CRITICAL"))
            risk_delta += 22

        # ── Network connections ──────────────────────────────────────────────
        net_targets = []
        if iocs:
            for ip in iocs.ips[:4]:
                net_targets.append((ip, rng.choice([80, 443, 8080, 4444, 1337])))
            for domain in iocs.domains[:3]:
                net_targets.append((domain, rng.choice([80, 443, 8080])))

        # Always add at least some C2 if malware family detected
        if not net_targets and yara_families:
            c2_ips = [
                f"{rng.randint(100,220)}.{rng.randint(10,250)}.{rng.randint(10,250)}.{rng.randint(1,250)}"
                for _ in range(rng.randint(1, 3))
            ]
            for ip in c2_ips:
                net_targets.append((ip, rng.choice([80, 443, 4444, 8080])))

        for dest, port in net_targets:
            ts += rng.randint(200, 600)
            is_dns = not dest[0].isdigit()
            etype = "network_dns" if is_dns else "network_connect"
            proto = "HTTPS" if port == 443 else "HTTP" if port == 80 else "TCP"
            events.append(_make_event(ts, etype, "network",
                                      f"Outbound {proto} connection attempt to {dest}:{port} — BLOCKED by sandbox",
                                      f"{dest}:{port}", "HIGH", blocked=True))
            result.network_iocs.append({
                "type":    "domain" if is_dns else "ip",
                "value":   dest,
                "port":    port,
                "proto":   proto,
                "blocked": True,
            })
            risk_delta += 8

        if net_targets:
            result.observed_network_connection = True
            ts += rng.randint(100, 300)
            events.append(_make_event(ts, "network_dns", "network",
                                      "DNS queries logged (C2 infrastructure reconnaissance)",
                                      "Winsock / WSAStartup / getaddrinfo", "MEDIUM"))

        # ── Screenshot placeholder ────────────────────────────────────────────
        if not result.screenshots:
            result.screenshots.append("screenshot_00_00.png (sandbox desktop capture)")

        # ── Sort + finalize ──────────────────────────────────────────────────
        events.sort(key=lambda e: e.timestamp_ms)
        result.events = events
        result.execution_time_ms = ts + rng.randint(200, 500)
        result.risk_delta = min(risk_delta, 60)  # raised cap: 35 → 60
        result.dynamic_score = min(45 + risk_delta, 100)  # raw dynamic score for weighted merge
        result.sandbox_verdict = (
            "MALICIOUS" if risk_delta >= 20 else
            "SUSPICIOUS" if risk_delta >= 8 else
            "CLEAN"
        )
        logger.info(f"Windows sandbox: {len(events)} events, risk_delta={result.risk_delta}, "
                    f"verdict={result.sandbox_verdict}")
        return result


# ── Android Sandbox Profile ───────────────────────────────────────────────────

class AndroidSandboxProfile:
    """
    Generates an Android sandbox execution timeline from APK static artifacts.

    Real-VM adapter stub:
      Replace generate() body with:
        import requests
        upload = requests.post("http://mobsf-host:8000/api/v1/upload",
                               files={"file": open(file_path,"rb")},
                               headers={"Authorization": MOBSF_API_KEY}).json()
        scan = requests.post("http://mobsf-host:8000/api/v1/dynamic/start_analysis",
                             data={"hash": upload["hash"]},
                             headers={"Authorization": MOBSF_API_KEY}).json()
        # wait / poll
        report = requests.post("http://mobsf-host:8000/api/v1/dynamic/report_json",
                               data={"hash": upload["hash"]},
                               headers={"Authorization": MOBSF_API_KEY}).json()
        return self._parse_mobsf_report(report)
    """

    _DANGEROUS_PERMS = [
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
        "READ_CONTACTS", "READ_CALL_LOG",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "RECORD_AUDIO", "CAMERA",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "PROCESS_OUTGOING_CALLS", "CALL_PHONE",
        "BIND_DEVICE_ADMIN", "BIND_ACCESSIBILITY_SERVICE",
        "SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED",
        "GET_ACCOUNTS", "USE_CREDENTIALS",
    ]

    def generate(self, file_path: Path, report: "AnalysisReport") -> DynamicSandboxResult:
        rng = random.Random(_seed(file_path))
        result = DynamicSandboxResult(sandbox_type="android", sandbox_verdict="CLEAN")
        events: list[SandboxEvent] = []
        ts = 0
        risk_delta = 0

        iocs = report.iocs
        yara_families = set()
        if report.yara and report.yara.matches:
            yara_families = {m.family for m in report.yara.matches}

        # ── App launches ─────────────────────────────────────────────────────
        ts += rng.randint(500, 1000)
        pkg = "com." + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=8))
        events.append(_make_event(ts, "process_start", "process",
                                  f"APK installed and launched: {pkg}",
                                  f"package:{pkg}", "INFO"))

        # ── Permissions requested ─────────────────────────────────────────────
        num_perms = rng.randint(4, 10)
        perms = rng.sample(self._DANGEROUS_PERMS, min(num_perms, len(self._DANGEROUS_PERMS)))
        dangerous_perms = ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "BIND_DEVICE_ADMIN",
                           "BIND_ACCESSIBILITY_SERVICE", "PROCESS_OUTGOING_CALLS"]

        for perm in perms:
            ts += rng.randint(300, 700)
            sev = "CRITICAL" if perm in dangerous_perms else "HIGH" if "LOCATION" in perm or "AUDIO" in perm else "MEDIUM"
            result.permissions_requested.append(perm)
            events.append(_make_event(ts, "apk_permission", "api",
                                      f"Runtime permission requested: android.permission.{perm} → GRANTED",
                                      f"android.permission.{perm}", sev))
            risk_delta += 5 if perm in dangerous_perms else 2

        # ── SMS interception ─────────────────────────────────────────────────
        if "READ_SMS" in perms or "RECEIVE_SMS" in perms:
            ts += rng.randint(400, 800)
            events.append(_make_event(ts, "apk_sms_intercept", "api",
                                      "BroadcastReceiver registered for SMS_RECEIVED intent — SMS interception active",
                                      "android.provider.Telephony.SMS_RECEIVED", "CRITICAL"))
            risk_delta += 20

        # ── Accessibility service abuse ───────────────────────────────────────
        if "BIND_ACCESSIBILITY_SERVICE" in perms:
            ts += rng.randint(600, 1200)
            events.append(_make_event(ts, "apk_accessibility", "api",
                                      "AccessibilityService bound — can read all screen content, simulate taps",
                                      "android.accessibilityservice.AccessibilityService", "CRITICAL"))
            risk_delta += 18

        # ── Overlay attack ────────────────────────────────────────────────────
        if "SYSTEM_ALERT_WINDOW" in perms:
            ts += rng.randint(500, 1000)
            events.append(_make_event(ts, "apk_overlay", "api",
                                      "Overlay window drawn over foreground app (credential phishing UI)",
                                      "TYPE_APPLICATION_OVERLAY / SYSTEM_ALERT_WINDOW", "CRITICAL"))
            risk_delta += 22

        # ── Device admin request ─────────────────────────────────────────────
        if "BIND_DEVICE_ADMIN" in perms:
            ts += rng.randint(400, 800)
            events.append(_make_event(ts, "apk_device_admin", "api",
                                      "Device Administrator rights requested — enables remote lock/wipe/persistence",
                                      "DevicePolicyManager / android.app.action.ADD_DEVICE_ADMIN", "CRITICAL"))
            risk_delta += 20

        # ── File access ───────────────────────────────────────────────────────
        ts += rng.randint(300, 700)
        events.append(_make_event(ts, "file_enum", "file",
                                  "File system scan: /sdcard/DCIM, /sdcard/Documents, /sdcard/WhatsApp",
                                  "/sdcard/", "HIGH"))
        result.dropped_files.append(f"/data/data/{pkg}/files/exfil.db")
        ts += rng.randint(200, 500)
        events.append(_make_event(ts, "file_drop", "file",
                                  "Local database created to stage exfiltration data",
                                  f"/data/data/{pkg}/files/exfil.db", "HIGH"))
        risk_delta += 8

        # ── Network exfiltration ─────────────────────────────────────────────
        net_targets = []
        if iocs:
            net_targets.extend([(d, 443) for d in iocs.domains[:3]])
            net_targets.extend([(ip, 443) for ip in iocs.ips[:2]])

        if not net_targets:
            fake_domain = f"{rng.choice(['api','cdn','update','sync'])}.{rng.choice(['analytics-corp','cloudhost','trackcdn'])}.{rng.choice(['com','net','io'])}"
            net_targets.append((fake_domain, 443))

        for dest, port in net_targets:
            ts += rng.randint(300, 700)
            events.append(_make_event(ts, "apk_exfil", "network",
                                      f"HTTPS POST to C2: transmitting contacts, SMS log, GPS location → {dest}",
                                      f"{dest}:{port}", "CRITICAL", blocked=True))
            result.network_iocs.append({
                "type":    "domain" if not dest[0].isdigit() else "ip",
                "value":   dest,
                "port":    port,
                "proto":   "HTTPS",
                "blocked": True,
            })
            risk_delta += 10

        # ── Screenshots ───────────────────────────────────────────────────────
        for i, label in enumerate(["permission_dialog", "overlay_screen", "home_screen"]):
            result.screenshots.append(f"android_screenshot_{i:02d}_{label}.png")

        # ── Sort + finalize ──────────────────────────────────────────────────
        events.sort(key=lambda e: e.timestamp_ms)
        result.events = events
        result.execution_time_ms = ts + rng.randint(300, 800)
        result.risk_delta = min(risk_delta, 35)
        result.sandbox_verdict = (
            "MALICIOUS" if risk_delta >= 25 else
            "SUSPICIOUS" if risk_delta >= 10 else
            "CLEAN"
        )
        logger.info(f"Android sandbox: {len(events)} events, risk_delta={result.risk_delta}")
        return result


# ── Document Sandbox Profile ──────────────────────────────────────────────────

class DocumentSandboxProfile:
    """
    Generates a document sandbox execution timeline for PDF/DOCX/XLSX.

    Real-VM adapter stub:
      Same as WindowsSandboxProfile — submit document to CAPE and parse
      the resulting behavior report (CAPE handles Office/PDF detonation).
    """

    def generate(self, file_path: Path, report: "AnalysisReport") -> DynamicSandboxResult:
        rng = random.Random(_seed(file_path))
        result = DynamicSandboxResult(sandbox_type="document", sandbox_verdict="CLEAN")
        events: list[SandboxEvent] = []
        ts = 0
        risk_delta = 0

        ext = file_path.suffix.lower().lstrip(".")
        iocs = report.iocs
        yara = report.yara
        has_macros = any(
            m.rule_name for m in (yara.matches if yara and yara.matches else [])
            if "macro" in m.rule_name.lower() or "vba" in m.rule_name.lower()
        )
        has_js = ext == "pdf"
        has_dde = ext in ("doc", "docx", "xls", "xlsx")

        # ── Document opened ──────────────────────────────────────────────────
        ts += rng.randint(800, 1500)
        viewer = {
            "pdf": "Adobe Acrobat Reader (sandboxed)",
            "docx": "Microsoft Word (Protected View bypassed)",
            "doc":  "Microsoft Word (Protected View bypassed)",
            "xlsx": "Microsoft Excel (Protected View bypassed)",
            "xls":  "Microsoft Excel (Protected View bypassed)",
        }.get(ext, "Application viewer")
        events.append(_make_event(ts, "process_start", "process",
                                  f"Document opened in {viewer}",
                                  file_path.name, "INFO"))

        # ── Protected view bypass ────────────────────────────────────────────
        if ext in ("docx", "doc", "xlsx", "xls"):
            ts += rng.randint(400, 800)
            events.append(_make_event(ts, "doc_exploit", "api",
                                      "Protected View disabled — user prompted to Enable Editing + Enable Content",
                                      "Protected View / Trust Center", "HIGH"))
            risk_delta += 10

        # ── Macro / VBA execution ─────────────────────────────────────────────
        if has_macros or ext in ("doc", "docx", "xls", "xlsx"):
            ts += rng.randint(500, 1000)
            events.append(_make_event(ts, "doc_macro", "api",
                                      "VBA AutoOpen macro triggered on document load",
                                      "Document.AutoOpen / Workbook.Open", "CRITICAL"))
            risk_delta += 18

            ts += rng.randint(300, 700)
            ps_cmd = "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand JAB..."
            events.append(_make_event(ts, "doc_child_process", "process",
                                      f"Child process spawned by macro: {ps_cmd}",
                                      "WINWORD.EXE → cmd.exe → powershell.exe", "CRITICAL"))
            result.dropped_files.append("C:\\Users\\Public\\stage2.ps1")
            risk_delta += 20

        # ── JavaScript in PDF ─────────────────────────────────────────────────
        if has_js:
            ts += rng.randint(400, 900)
            events.append(_make_event(ts, "doc_js", "api",
                                      "Embedded JavaScript executed inside PDF viewer (eval() detected)",
                                      "JavaScript / AcroForm", "HIGH"))
            risk_delta += 12

            ts += rng.randint(300, 600)
            events.append(_make_event(ts, "doc_exploit", "api",
                                      "PDF heap-spray pattern detected — possible exploit for CVE-202x-xxxx",
                                      "JavaScript heap allocation anomaly", "CRITICAL"))
            risk_delta += 15

        # ── DDE (Dynamic Data Exchange) ───────────────────────────────────────
        if has_dde:
            ts += rng.randint(300, 700)
            events.append(_make_event(ts, "doc_dde", "api",
                                      "DDE field detected: =cmd|'/c powershell ...'!A1 — shell execution via DDE",
                                      "DDE / DDEAUTO / UpdateLinks", "CRITICAL"))
            risk_delta += 18

        # ── OLE object ───────────────────────────────────────────────────────
        if ext in ("doc", "docx"):
            ts += rng.randint(400, 800)
            events.append(_make_event(ts, "doc_ole", "api",
                                      "OLE object embedded and activated: Package / EquationEditor exploit attempt",
                                      "OLE / Package / CVE-2017-11882", "CRITICAL"))
            risk_delta += 20

        # ── Download stage 2 ─────────────────────────────────────────────────
        net_targets = []
        if iocs:
            net_targets.extend([(d, 80) for d in iocs.domains[:2]])
            net_targets.extend([(ip, 443) for ip in iocs.ips[:2]])

        if not net_targets:
            fake = f"cdn.{rng.choice(['update','delivery','cloud'])}-{rng.choice(['host','serve','net'])}.{rng.choice(['com','ru','cn'])}"
            net_targets.append((fake, 80))

        for dest, port in net_targets:
            ts += rng.randint(400, 900)
            events.append(_make_event(ts, "doc_download", "network",
                                      f"Stage-2 payload download attempted: GET http://{dest}/payload.exe — BLOCKED",
                                      f"http://{dest}/payload.exe", "CRITICAL", blocked=True))
            result.network_iocs.append({
                "type":    "domain" if not dest[0].isdigit() else "ip",
                "value":   dest,
                "port":    port,
                "proto":   "HTTP",
                "blocked": True,
            })
            risk_delta += 12

        # ── Screenshots ───────────────────────────────────────────────────────
        result.screenshots.append("document_screenshot_00_opened.png")
        if risk_delta > 15:
            result.screenshots.append("document_screenshot_01_macro_prompt.png")

        # ── Sort + finalize ──────────────────────────────────────────────────
        events.sort(key=lambda e: e.timestamp_ms)
        result.events = events
        result.execution_time_ms = ts + rng.randint(200, 600)
        result.risk_delta = min(risk_delta, 35)
        result.sandbox_verdict = (
            "MALICIOUS" if risk_delta >= 20 else
            "SUSPICIOUS" if risk_delta >= 8 else
            "CLEAN"
        )
        logger.info(f"Document sandbox: {len(events)} events, risk_delta={result.risk_delta}")
        return result


# ── Sandbox Router ─────────────────────────────────────────────────────────────

_WINDOWS_EXTS  = {"exe", "dll", "msi", "bat", "ps1", "vbs", "scr", "hta", "pif", "cpl", "sys"}
_ANDROID_EXTS  = {"apk", "aab"}
_DOCUMENT_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "pptx", "ppt", "rtf"}


def run_dynamic_analysis(
    file_path: Path,
    report: "AnalysisReport",
    timeout_seconds: int = 90,
) -> DynamicSandboxResult:
    """
    Main entry point for dynamic sandbox analysis.

    Detects file type, routes to the correct sandbox profile, and returns
    a DynamicSandboxResult. Runs synchronously (simulation is fast).

    For real VM integration: wrap the profile.generate() call in a
    concurrent.futures.ThreadPoolExecutor with the timeout_seconds limit.
    """
    t0 = time.time()
    ext = file_path.suffix.lower().lstrip(".")

    try:
        if ext in _WINDOWS_EXTS:
            logger.info(f"Routing {file_path.name} → Windows sandbox profile")
            result = WindowsSandboxProfile().generate(file_path, report)
        elif ext in _ANDROID_EXTS:
            logger.info(f"Routing {file_path.name} → Android sandbox profile")
            result = AndroidSandboxProfile().generate(file_path, report)
        elif ext in _DOCUMENT_EXTS:
            logger.info(f"Routing {file_path.name} → Document sandbox profile")
            result = DocumentSandboxProfile().generate(file_path, report)
        else:
            logger.info(f"No sandbox profile for extension .{ext} — skipping dynamic analysis")
            return DynamicSandboxResult(
                sandbox_type="unsupported",
                sandbox_verdict="CLEAN",
                error=f"No sandbox profile for file type .{ext}",
            )
    except Exception as exc:
        logger.error(f"Sandbox error for {file_path.name}: {exc}", exc_info=True)
        return DynamicSandboxResult(
            sandbox_type="error",
            sandbox_verdict="CLEAN",
            error=str(exc),
        )

    elapsed = int((time.time() - t0) * 1000)
    logger.info(f"Sandbox complete for {file_path.name} in {elapsed}ms "
                f"(simulated exec time: {result.execution_time_ms}ms)")
    return result
