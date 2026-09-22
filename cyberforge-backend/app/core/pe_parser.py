"""
CyberForge — PE File Parser
Uses pefile to extract deep forensic metadata from Windows executables.
Detects packers, suspicious imports, anomalies, and more.
"""
import math
import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ── Known suspicious API functions ──────────────────────────────────────
SUSPICIOUS_IMPORTS = {
    # Process injection
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "SetThreadContext",
    "GetThreadContext", "QueueUserAPC", "NtQueueApcThread",
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory",

    # Process hollowing
    "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
    "CreateProcessA", "CreateProcessW", "ResumeThread", "SuspendThread",

    # Credential access
    "OpenProcessToken", "AdjustTokenPrivileges", "LsaOpenPolicy",
    "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",

    # Persistence
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "CreateServiceA", "OpenServiceA", "StartServiceA",

    # Evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA",
    "GetTickCount", "timeGetTime",

    # Networking
    "WSAStartup", "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "WSAConnect", "InternetOpenA", "InternetConnectA",
    "HttpSendRequestA", "URLDownloadToFileA",

    # File system
    "DeleteFileA", "MoveFileExA", "FindFirstFileA",
    "GetTempPathA", "GetTempFileNameA",
}

# ── Known packer signatures (section names) ─────────────────────────────
PACKER_SIGNATURES = {
    "UPX0":      "UPX",
    "UPX1":      "UPX",
    "UPX2":      "UPX",
    ".UPX0":     "UPX",
    ".UPX1":     "UPX",
    ".MPRESS1":  "MPRESS",
    ".MPRESS2":  "MPRESS",
    "ASPack":    "ASPack",
    ".ASPack":   "ASPack",
    ".adata":    "Generic Packer",
    ".Upack":    "Upack",
    ".petite":   "Petite",
    "PEtite":    "Petite",
    ".neolit":   "NeoliteUnpacker",
    ".enigma1":  "Enigma",
    ".enigma2":  "Enigma",
}

# ── Compile time epoch limits ────────────────────────────────────────────
UNIX_EPOCH = datetime.datetime(1970, 1, 1)
FUTURE_DATE = datetime.datetime(2030, 1, 1)


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    permissions: str        # e.g. "RWX", "R-X"
    md5: str
    suspicious: bool
    reason: str = ""


@dataclass
class PEImport:
    dll: str
    functions: list[str] = field(default_factory=list)
    suspicious_count: int = 0
    suspicious_funcs: list[str] = field(default_factory=list)


@dataclass
class PEResult:
    # Basic info
    machine_type: str = ""
    machine_type_desc: str = ""
    subsystem: str = ""
    is_64bit: bool = False
    is_dll: bool = False
    is_driver: bool = False
    compile_time: Optional[str] = None
    compile_time_suspicious: bool = False

    # Headers
    entry_point: str = ""
    image_base: str = ""
    number_of_sections: int = 0
    characteristics: list[str] = field(default_factory=list)

    # Sections
    sections: list[PESection] = field(default_factory=list)
    high_entropy_sections: int = 0     # sections with entropy > 7.0

    # Imports
    imports: list[PEImport] = field(default_factory=list)
    total_suspicious_imports: int = 0
    import_hash: Optional[str] = None

    # Exports
    exports: list[str] = field(default_factory=list)

    # Anomalies & detection
    packer_detected: Optional[str] = None
    overlay_detected: bool = False
    overlay_entropy: Optional[float] = None
    anomalies: list[str] = field(default_factory=list)

    # Strings of interest (found in the binary)
    interesting_strings: list[str] = field(default_factory=list)

    # ── Heuristic API category flags (set by parse_pe) ──────────────
    # True when the classic injection triad is ALL present
    has_injection_triad: bool = False
    # True when NT/Zw low-level syscall wrappers are imported (EDR evasion)
    has_nt_evasion_apis: bool = False
    # True when networking APIs are present (socket/WinInet family)
    has_network_apis: bool = False
    # True when crypto APIs are present (Crypt* / BCrypt*)
    has_crypto_apis: bool = False
    # True when file enumeration APIs are present (FindFirstFile etc.)
    has_file_enum_apis: bool = False
    # True when the binary imports only LoadLibrary/GetProcAddress (manual API loading)
    dynamic_import_resolution: bool = False
    # True when a known packer section name is found — enforce minimum MEDIUM verdict
    force_minimum_medium: bool = False

    def to_dict(self) -> dict:
        return {
            "machine_type": self.machine_type,
            "machine_type_desc": self.machine_type_desc,
            "subsystem": self.subsystem,
            "is_64bit": self.is_64bit,
            "is_dll": self.is_dll,
            "compile_time": self.compile_time,
            "compile_time_suspicious": self.compile_time_suspicious,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "number_of_sections": self.number_of_sections,
            "characteristics": self.characteristics,
            "sections": [
                {
                    "name": s.name,
                    "virtual_address": hex(s.virtual_address),
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": s.entropy,
                    "permissions": s.permissions,
                    "md5": s.md5,
                    "suspicious": s.suspicious,
                    "reason": s.reason,
                }
                for s in self.sections
            ],
            "high_entropy_sections": self.high_entropy_sections,
            "imports": [
                {
                    "dll": imp.dll,
                    "functions": imp.functions,
                    "suspicious_count": imp.suspicious_count,
                    "suspicious_functions": imp.suspicious_funcs,
                }
                for imp in self.imports
            ],
            "total_suspicious_imports": self.total_suspicious_imports,
            "import_hash": self.import_hash,
            "exports": self.exports,
            "packer_detected": self.packer_detected,
            "overlay_detected": self.overlay_detected,
            "overlay_entropy": self.overlay_entropy,
            "anomalies": self.anomalies,
            "interesting_strings": self.interesting_strings,
            # Heuristic flags
            "has_injection_triad": self.has_injection_triad,
            "has_nt_evasion_apis": self.has_nt_evasion_apis,
            "has_network_apis": self.has_network_apis,
            "has_crypto_apis": self.has_crypto_apis,
            "has_file_enum_apis": self.has_file_enum_apis,
            "dynamic_import_resolution": self.dynamic_import_resolution,
            "force_minimum_medium": self.force_minimum_medium,
        }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    l = len(data)
    for c in freq.values():
        p = c / l
        ent -= p * math.log2(p)
    return round(ent, 4)


def _section_perms(section) -> str:
    r = "R" if section.Characteristics & 0x40000000 else "-"
    w = "W" if section.Characteristics & 0x80000000 else "-"
    x = "X" if section.Characteristics & 0x20000000 else "-"
    return f"{r}{w}{x}"


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    import re
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [s.decode("ascii", errors="ignore") for s in pattern.findall(data)]


def _flag_interesting_strings(strings: list[str]) -> list[str]:
    """Filter strings for IoC patterns and suspicious content."""
    import re
    interesting = []
    patterns = [
        (re.compile(r"https?://[^\s\"'<>]{8,}"), "URL"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP"),
        (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "Email"),
        (re.compile(r"(?:HKCU|HKLM|HKEY_[A-Z_]+)\\[^\x00]{4,}"), "Registry Key"),
        (re.compile(r"(?:vssadmin|bcdedit|wbadmin|cmd\.exe|powershell)", re.IGNORECASE), "Suspicious CMD"),
        (re.compile(r"(?:base64|gzip|deflate|XOR|RC4|AES)", re.IGNORECASE), "Crypto/Encoding"),
        (re.compile(r"\.(?:exe|dll|bat|vbs|ps1|cmd)\b", re.IGNORECASE), "Executable Reference"),
        (re.compile(r"(?:password|passwd|credential|token|apikey)", re.IGNORECASE), "Credential String"),
        (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "Possible Base64"),
    ]
    seen = set()
    for s in strings:
        for pattern, label in patterns:
            if pattern.search(s) and s not in seen:
                seen.add(s)
                interesting.append(f"[{label}] {s[:120]}")
                break
    return interesting[:50]  # cap at 50


def _get_machine_desc(machine_type: int) -> tuple[str, str]:
    types = {
        0x014c: ("I386",   "x86 32-bit"),
        0x8664: ("AMD64",  "x86-64 64-bit"),
        0x01c0: ("ARM",    "ARM 32-bit"),
        0xaa64: ("ARM64",  "ARM 64-bit"),
        0x0200: ("IA64",   "Intel Itanium"),
    }
    t = types.get(machine_type, (hex(machine_type), "Unknown"))
    return t[0], t[1]


def _get_subsystem(sub: int) -> str:
    subs = {
        1: "Native",
        2: "GUI (Windows)",
        3: "Console (CUI)",
        5: "OS/2 CUI",
        7: "POSIX CUI",
        9: "Windows CE",
        10: "EFI Application",
        14: "Xbox",
    }
    return subs.get(sub, f"Unknown ({sub})")


def _get_characteristics(chars: int) -> list[str]:
    flags = []
    if chars & 0x0002: flags.append("Executable")
    if chars & 0x0020: flags.append("Large Address Aware")
    if chars & 0x0100: flags.append("32-bit Word Machine")
    if chars & 0x0200: flags.append("Debug Info Stripped")
    if chars & 0x2000: flags.append("DLL")
    if chars & 0x4000: flags.append("System File")
    return flags


def parse_pe(file_path: Path) -> Optional[PEResult]:
    """
    Full PE file analysis. Returns None if file is not a valid PE.
    """
    if not PEFILE_AVAILABLE:
        return None

    result = PEResult()
    anomalies = []

    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError:
        return None
    except Exception:
        return None

    try:
        # ── Basic header info ──────────────────────────────────
        machine = pe.FILE_HEADER.Machine
        result.machine_type, result.machine_type_desc = _get_machine_desc(machine)
        result.is_64bit = (machine == 0x8664)
        result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result.is_driver = bool(pe.FILE_HEADER.Characteristics & 0x1000)
        result.characteristics = _get_characteristics(pe.FILE_HEADER.Characteristics)
        result.number_of_sections = pe.FILE_HEADER.NumberOfSections

        # Optional header
        result.entry_point  = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        result.image_base   = hex(pe.OPTIONAL_HEADER.ImageBase)
        result.subsystem    = _get_subsystem(pe.OPTIONAL_HEADER.Subsystem)

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_dt = datetime.datetime.utcfromtimestamp(ts)
            result.compile_time = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            if compile_dt < UNIX_EPOCH or compile_dt > FUTURE_DATE:
                result.compile_time_suspicious = True
                anomalies.append("Suspicious compile timestamp (likely forged)")
        except Exception:
            result.compile_time = f"Invalid ({ts})"
            result.compile_time_suspicious = True

        # ── PE Sections ────────────────────────────────────────
        high_entropy = 0
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00").strip()
            data = section.get_data()
            ent  = _entropy(data)
            perm = _section_perms(section)
            md5  = __import__("hashlib").md5(data).hexdigest()
            vsize = section.Misc_VirtualSize
            rsize = section.SizeOfRawData

            suspicious = False
            reason = ""

            # High entropy = packed/encrypted
            if ent > 7.2:
                suspicious = True
                reason = f"Very high entropy ({ent}) — likely encrypted/packed payload"
                high_entropy += 1
            elif ent > 6.5:
                suspicious = True
                reason = f"High entropy ({ent}) — possible compression or obfuscation"
                high_entropy += 1

            # Executable data section
            if "W" in perm and "X" in perm:
                suspicious = True
                reason = (reason + " | " if reason else "") + "RWX section — classic code injection target"
                anomalies.append(f"Section '{name}' has RWX permissions (write+execute)")

            # Virtual size >> raw size (common packer trick)
            if rsize > 0 and vsize > rsize * 10:
                suspicious = True
                reason = (reason + " | " if reason else "") + "VirtualSize >> RawSize (decompresses in memory)"

            # Known packer name
            if name in PACKER_SIGNATURES:
                result.packer_detected = PACKER_SIGNATURES[name]
                suspicious = True
                reason = (reason + " | " if reason else "") + f"Packer section name: {PACKER_SIGNATURES[name]}"

            result.sections.append(PESection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=vsize,
                raw_size=rsize,
                entropy=ent,
                permissions=perm,
                md5=md5,
                suspicious=suspicious,
                reason=reason,
            ))

        result.high_entropy_sections = high_entropy

        # Anomaly: no sections
        if result.number_of_sections == 0:
            anomalies.append("PE has no sections — extremely suspicious")

        # Anomaly: too many sections
        if result.number_of_sections > 20:
            anomalies.append(f"Unusually high section count ({result.number_of_sections})")

        # ── Import Table ───────────────────────────────────────
        _INJECTION_TRIAD = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
        _NT_EVASION = {"NtAllocateVirtualMemory", "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
                       "ZwUnmapViewOfSection", "NtUnmapViewOfSection", "NtCreateThreadEx",
                       "NtQueryInformationProcess"}
        _NETWORK_APIS = {"WSAStartup", "socket", "connect", "InternetOpenA", "InternetConnectA",
                         "HttpSendRequestA", "URLDownloadToFileA", "WSAConnect", "send", "recv"}
        _CRYPTO_APIS = {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt",
                        "BCryptDecrypt", "CryptAcquireContextA", "BCryptGenerateSymmetricKey"}
        _FILE_ENUM_APIS = {"FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
                           "GetLogicalDrives", "GetDriveTypeA"}
        _DYNAMIC_LOAD_ONLY = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}

        total_sus = 0
        all_imported_funcs: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                funcs, sus_funcs = [], []

                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode("utf-8", errors="replace")
                        funcs.append(fname)
                        all_imported_funcs.add(fname)
                        if fname in SUSPICIOUS_IMPORTS:
                            sus_funcs.append(fname)

                result.imports.append(PEImport(
                    dll=dll_name,
                    functions=funcs,
                    suspicious_count=len(sus_funcs),
                    suspicious_funcs=sus_funcs,
                ))
                total_sus += len(sus_funcs)

        result.total_suspicious_imports = total_sus

        # ── Heuristic API category flags ───────────────────────
        result.has_injection_triad   = _INJECTION_TRIAD.issubset(all_imported_funcs)
        result.has_nt_evasion_apis   = bool(_NT_EVASION & all_imported_funcs)
        result.has_network_apis      = bool(_NETWORK_APIS & all_imported_funcs)
        result.has_crypto_apis       = bool(_CRYPTO_APIS & all_imported_funcs)
        result.has_file_enum_apis    = bool(_FILE_ENUM_APIS & all_imported_funcs)

        # Dynamic import resolution: zero imports OR only LoadLibrary/GetProcAddress
        if len(all_imported_funcs) == 0:
            result.dynamic_import_resolution = True
            anomalies.append("No imports detected — possibly manually imports APIs at runtime (suspicious)")
        elif len(result.imports) == 1 and all_imported_funcs.issubset(_DYNAMIC_LOAD_ONLY | {"GetProcAddress", "LoadLibraryA", "LoadLibraryW"}):
            result.dynamic_import_resolution = True
            anomalies.append("Only LoadLibrary/GetProcAddress imported — dynamic API resolution (evasion technique)")
        elif len(result.imports) == 1:
            anomalies.append("Only 1 import DLL detected — may use dynamic import resolution")

        # Force minimum MEDIUM if packer section names detected
        result.force_minimum_medium = result.packer_detected is not None

        # ── Import Hash ────────────────────────────────────────
        try:
            result.import_hash = pe.get_imphash()
        except Exception:
            pass

        # ── Exports ────────────────────────────────────────────
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result.exports.append(exp.name.decode("utf-8", errors="replace"))

        # ── Overlay detection ──────────────────────────────────
        overlay_off = pe.get_overlay_data_start_offset()
        if overlay_off:
            result.overlay_detected = True
            with open(file_path, "rb") as f:
                f.seek(overlay_off)
                overlay_data = f.read(min(65536, 1024 * 1024))  # max 1MB
            result.overlay_entropy = _entropy(overlay_data)
            if result.overlay_entropy > 7.0:
                anomalies.append(f"High-entropy overlay detected (offset {hex(overlay_off)}, entropy {result.overlay_entropy}) — embedded payload?")
            else:
                anomalies.append(f"Overlay data detected at offset {hex(overlay_off)}")

        # ── Interesting strings ────────────────────────────────
        with open(file_path, "rb") as f:
            raw_data = f.read()
        all_strings = _extract_strings(raw_data)
        result.interesting_strings = _flag_interesting_strings(all_strings)

        result.anomalies = anomalies
        pe.close()

    except Exception as e:
        result.anomalies.append(f"Parse warning: {str(e)}")

    return result
