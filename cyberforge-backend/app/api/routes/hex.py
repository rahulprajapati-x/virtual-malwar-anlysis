"""
CyberForge — Advanced Hex Analyzer & Forensic Artifact Engine v2.0
Professional-grade binary analysis with intelligent pattern detection,
MITRE ATT&CK mapping, AI risk scoring, YARA/Sigma export, and multi-format IOC export.
"""
import base64
import csv
import io
import json
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Sample

router = APIRouter(prefix="/api/samples", tags=["Hex Analyzer"])


class HexSearchRequest(BaseModel):
    query: str
    search_type: str  # "hex", "ascii", "unicode"


# ─────────────────────────────────────────────────────────────────────────────
#  MITRE ATT&CK TECHNIQUE MAPPING
#  Maps artifact types → list of (technique_id, technique_name, tactic)
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAP: dict[str, list[dict]] = {
    "suspicious_api": [
        {"id": "T1055",  "name": "Process Injection",           "tactic": "Defense Evasion"},
        {"id": "T1106",  "name": "Native API",                  "tactic": "Execution"},
    ],
    "encoded_powershell": [
        {"id": "T1059.001", "name": "PowerShell",               "tactic": "Execution"},
        {"id": "T1027",     "name": "Obfuscated Files or Info", "tactic": "Defense Evasion"},
    ],
    "powershell": [
        {"id": "T1059.001", "name": "PowerShell",               "tactic": "Execution"},
    ],
    "cmd_command": [
        {"id": "T1059.003", "name": "Windows Command Shell",    "tactic": "Execution"},
    ],
    "registry_key": [
        {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
        {"id": "T1112",     "name": "Modify Registry",          "tactic": "Defense Evasion"},
    ],
    "url": [
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
        {"id": "T1105",     "name": "Ingress Tool Transfer",    "tactic": "Command and Control"},
    ],
    "ipv4": [
        {"id": "T1071",  "name": "Application Layer Protocol",  "tactic": "Command and Control"},
        {"id": "T1219",  "name": "Remote Access Software",      "tactic": "Command and Control"},
    ],
    "ipv6": [
        {"id": "T1071",  "name": "Application Layer Protocol",  "tactic": "Command and Control"},
    ],
    "domain": [
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
        {"id": "T1568",     "name": "Dynamic Resolution",       "tactic": "Command and Control"},
    ],
    "c2_endpoint": [
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
        {"id": "T1573",     "name": "Encrypted Channel",        "tactic": "Command and Control"},
    ],
    "discord_webhook": [
        {"id": "T1102.001", "name": "Dead Drop Resolver",       "tactic": "Command and Control"},
        {"id": "T1041",     "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "telegram_token": [
        {"id": "T1102",  "name": "Web Service",                 "tactic": "Command and Control"},
        {"id": "T1041",  "name": "Exfiltration Over C2 Channel","tactic": "Exfiltration"},
    ],
    "cloud_storage": [
        {"id": "T1567.002", "name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration"},
        {"id": "T1105",     "name": "Ingress Tool Transfer",    "tactic": "Command and Control"},
    ],
    "base64_blob": [
        {"id": "T1027",  "name": "Obfuscated Files or Info",    "tactic": "Defense Evasion"},
        {"id": "T1140",  "name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    ],
    "windows_path": [
        {"id": "T1547",  "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
        {"id": "T1036",  "name": "Masquerading",                "tactic": "Defense Evasion"},
    ],
    "linux_path": [
        {"id": "T1547",  "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    ],
    "mutex": [
        {"id": "T1480",  "name": "Execution Guardrails",        "tactic": "Defense Evasion"},
    ],
    "ngrok_tunnel": [
        {"id": "T1572",  "name": "Protocol Tunneling",          "tactic": "Command and Control"},
        {"id": "T1090",  "name": "Proxy",                       "tactic": "Command and Control"},
    ],
    "tor_service": [
        {"id": "T1090.003", "name": "Multi-hop Proxy",          "tactic": "Command and Control"},
    ],
    "named_pipe": [
        {"id": "T1559.001", "name": "Component Object Model",   "tactic": "Execution"},
        {"id": "T1570",     "name": "Lateral Tool Transfer",    "tactic": "Lateral Movement"},
    ],
    "email": [
        {"id": "T1071.003", "name": "Mail Protocols",           "tactic": "Command and Control"},
    ],
    "dll_name": [
        {"id": "T1574.001", "name": "DLL Search Order Hijacking", "tactic": "Defense Evasion"},
        {"id": "T1129",     "name": "Shared Modules",           "tactic": "Execution"},
    ],
    "user_agent": [
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
    ],
    "c2_framework": [
        {"id": "T1059.001", "name": "PowerShell",               "tactic": "Execution"},
        {"id": "T1055",     "name": "Process Injection",        "tactic": "Defense Evasion"},
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
        {"id": "T1573",     "name": "Encrypted Channel",        "tactic": "Command and Control"},
    ],
    "ddns_domain": [
        {"id": "T1568.001", "name": "Fast Flux DNS",            "tactic": "Command and Control"},
        {"id": "T1071.001", "name": "Web Protocols",            "tactic": "Command and Control"},
        {"id": "T1572",     "name": "Protocol Tunneling",       "tactic": "Command and Control"},
    ],
    "credential": [
        {"id": "T1555",     "name": "Credentials from Password Stores", "tactic": "Credential Access"},
        {"id": "T1552",     "name": "Unsecured Credentials",   "tactic": "Credential Access"},
    ],
    "api_key": [
        {"id": "T1552.001", "name": "Credentials In Files",     "tactic": "Credential Access"},
        {"id": "T1528",     "name": "Steal Application Access Token", "tactic": "Credential Access"},
    ],
    "crypto_wallet": [
        {"id": "T1657",     "name": "Financial Theft",          "tactic": "Impact"},
    ],
    "jwt_token": [
        {"id": "T1528",     "name": "Steal Application Access Token", "tactic": "Credential Access"},
    ],
    "ssh_key": [
        {"id": "T1552.004", "name": "Private Keys",             "tactic": "Credential Access"},
    ],
    "ip_port": [
        {"id": "T1071",     "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1219",     "name": "Remote Access Software",   "tactic": "Command and Control"},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
#  RECOMMENDED ACTIONS PER ARTIFACT TYPE
# ─────────────────────────────────────────────────────────────────────────────

ACTIONS: dict[str, str] = {
    "suspicious_api":    "Investigate process memory and loaded modules. Run PE import analysis.",
    "encoded_powershell":"Decode the Base64 payload immediately. Check for IEX/download cradles.",
    "powershell":        "Review the PowerShell execution context. Check event logs (4104).",
    "cmd_command":       "Review command-line arguments. Check parent process chain.",
    "registry_key":      "Check registry key for persistence. Review run keys and scheduled tasks.",
    "url":               "Do NOT visit URL. Check DNS and proxy logs. Submit to threat intel.",
    "ipv4":              "Look up IP in threat intel feeds. Check firewall logs for connections.",
    "ipv6":              "Look up IPv6 in threat intel. Check for tunnel or proxy usage.",
    "domain":            "Check domain age/WHOIS. Submit to VirusTotal. Block at DNS level.",
    "c2_endpoint":       "HIGH PRIORITY: Block endpoint at firewall. Check for beacon traffic.",
    "discord_webhook":   "Revoke webhook if accessible. Check for exfiltrated data.",
    "telegram_token":    "Revoke Telegram bot token immediately. Check message history.",
    "cloud_storage":     "Check for exfiltrated files. Investigate storage account access logs.",
    "base64_blob":       "Decode the payload and re-analyze the decoded content.",
    "windows_path":      "Check if the path exists on infected hosts. Examine file contents.",
    "linux_path":        "Check persistence mechanisms in /etc/cron*, /etc/init.d/.",
    "mutex":             "Search for mutex name on threat intel. Identifies malware family.",
    "ngrok_tunnel":      "HIGH PRIORITY: Block *.ngrok.io at DNS/firewall. Check tunnel ID.",
    "tor_service":       "Block Tor exit nodes. Check for .onion proxy usage on network.",
    "named_pipe":        "Investigate IPC usage. Check for lateral movement via named pipes.",
    "email":             "Check for phishing or exfil via email. Verify sender domain.",
    "dll_name":          "Verify DLL path and integrity. Check for DLL hijacking.",
    "user_agent":        "Check proxy logs for this user-agent string. May indicate RAT.",
    "c2_framework":      "CRITICAL: Known C2/RAT framework string detected. Isolate system immediately.",
    "ddns_domain":       "HIGH PRIORITY: Block DDNS domain at DNS level. Likely dynamic C2 infrastructure.",
    "credential":        "Hardcoded credential detected — change passwords immediately and audit access logs.",
    "api_key":           "Hardcoded API key/token detected — revoke immediately and rotate credentials.",
    "crypto_wallet":     "Cryptocurrency wallet address — possible cryptominer or financial theft target.",
    "jwt_token":         "JWT token detected — may be stolen auth token. Revoke and re-authenticate.",
    "ssh_key":           "SSH private key material detected — rotate keys immediately.",
    "ip_port":           "IP:Port combination — likely C2 server address. Block at firewall immediately.",
}


# ─────────────────────────────────────────────────────────────────────────────
#  SUSPICIOUS TLDS
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    b"ru", b"cn", b"tk", b"pw", b"cc", b"xyz", b"top", b"club",
    b"work", b"link", b"click", b"download", b"gq", b"ml", b"cf", b"ga"
}


# ─────────────────────────────────────────────────────────────────────────────
#  ARTIFACT PATTERN REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = {
    # ── Network Indicators ────────────────────────────────────────────────
    "ipv4": {
        "regex": re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            rb'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        "color": "#EF4444",
        "risk": "HIGH",
        "confidence": 85,
        "label": "IPv4 Address",
        "confirmed": True,
    },
    "ipv6": {
        "regex": re.compile(
            rb'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            rb'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
            rb'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
        ),
        "color": "#EF4444",
        "risk": "HIGH",
        "confidence": 75,
        "label": "IPv6 Address",
        "confirmed": True,
    },
    "ip_port": {
        "regex": re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            rb'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
            rb'[:\x00](?:[1-9]\d{0,4})\b'
        ),
        "color": "#EF4444",
        "risk": "CRITICAL",
        "confidence": 92,
        "label": "IP:Port",
        "confirmed": True,
    },
    "url": {
        "regex": re.compile(
            rb'(?i)(?:https?|ftp|ftps|smb|ldap)://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,300}'
        ),
        "color": "#F97316",
        "risk": "HIGH",
        "confidence": 90,
        "label": "URL",
        "confirmed": True,
    },
    "domain": {
        "regex": re.compile(
            rb'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            rb'(?:com|net|org|io|ru|cn|xyz|biz|info|cc|tk|pw|top|club|'
            rb'work|link|click|download|gq|ml|cf|ga|gov|edu|mil|int|co|'
            rb'duckdns|no-ip|dyndns|ddns|afraid|freedns|dynv6|sytes|'
            rb'hopto|zapto|myftp|ngrok|serveo|pagekite)\b'
        ),
        "color": "#EF4444",
        "risk": "MEDIUM",
        "confidence": 70,
        "label": "Domain",
        "confirmed": False,
    },
    "email": {
        "regex": re.compile(
            rb'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
        ),
        "color": "#94A3B8",
        "risk": "MEDIUM",
        "confidence": 85,
        "label": "Email Address",
        "confirmed": True,
    },

    # ── C2 Indicators ─────────────────────────────────────────────────────
    "c2_endpoint": {
        "regex": re.compile(
            rb'(?i)(?:'
            # Classic C2 gate/panel paths
            rb'/gate(?:\.php)?|/panel(?:\.php)?|/checkin(?:\.php)?|'
            rb'/beacon(?:\.php)?|/callback(?:\.php)?|/update(?:\.php)?|'
            rb'/report(?:\.php)?|/tasks(?:\.php)?|/cmd(?:\.php)?|'
            rb'/upload(?:\.php)?|/collect(?:\.php)?|/post(?:\.php)?|'
            rb'/ping(?:\.php)?|/poll(?:\.php)?|/helo(?:\.php)?|'
            rb'/connect(?:\.php)?|/auth(?:\.php)?|/register(?:\.php)?|'
            rb'/heartbeat(?:\.php)?|/sync(?:\.php)?|/status(?:\.php)?|'
            # Cobalt Strike specific
            rb'/submit\.php|/cab\.asp|/api/v1/beacon|/rest/v2/agent|'
            rb'/__utm\.gif|/pixel\.gif|/jquery-[0-9.]+\.min\.js|'
            rb'/updates(?:\.php)?|/push(?:\.php)?|'
            # Metasploit / Meterpreter
            rb'/TnBqS|/HsFvB|/metsvc|/MultiHandler|'
            rb'/shell(?:\.php)?|/exec(?:\.php)?|/payload(?:\.php)?|'
            # RAT C2 paths
            rb'/rat(?:\.php)?|/c2(?:\.php)?|/cc(?:\.php)?|'
            rb'/command(?:\.php)?|/ctrl(?:\.php)?|/control(?:\.php)?|'
            rb'/agent(?:\.php)?|/implant(?:\.php)?|/bot(?:\.php)?|'
            rb'/zombie(?:\.php)?|/slave(?:\.php)?|/client(?:\.php)?|'
            rb'/task(?:\.php)?|/job(?:\.php)?|/work(?:\.php)?|'
            rb'/data(?:\.php)?|/info(?:\.php)?|/exfil(?:\.php)?'
            rb')'
        ),
        "color": "#EF4444",
        "risk": "CRITICAL",
        "confidence": 90,
        "label": "C2 Endpoint",
        "confirmed": True,
    },
    "c2_framework": {
        "regex": re.compile(
            rb'(?i)(?:'
            # Cobalt Strike
            rb'cobaltstrike|cobalt.strike|sleeptime|jitter|spawnto|'
            rb'prepend_sleep|sleep_mask|artifact.kit|ReflectiveDll|'
            rb'memdump|post-ex|named.pipe.stager|'
            # Metasploit/Meterpreter
            rb'meterpreter|metsrv|msfvenom|metasploit|'
            rb'ReflectiveLoader|ReflectiveDllInjection|'
            rb'SetThreadContext|CreateRemoteThread.*VirtualAlloc|'
            # Sliver
            rb'sliver.implant|sliverpb|implants\.Implant|'
            # Havoc
            rb'HavocC2|havoc.c2|teamserver.exe|'
            # Brute Ratel
            rb'bruteratel|brute.ratel|brc4|badger\.bin|'
            # Empire / PoshC2
            rb'powershell.empire|poshc2|invoke.empire|'
            # Common RAT families
            rb'AsyncRAT|async.rat|NjRAT|njrat|DarkComet|darkcomet|'
            rb'RemcosRAT|remcos.rat|QuasarRAT|quasar.rat|'
            rb'NanoCore|nanocore.rat|XWorm|xworm|DCRat|dcrat|'
            rb'LimeRAT|lime.rat|WarzoneRAT|warzone.rat|'
            rb'BitRAT|bit.rat|Gh0stRAT|gh0st.rat|Orcus|orcusrat|'
            rb'BlackShades|blackshades|Luminosity|luminosity.link|'
            rb'AndroRAT|androrat|DroidJack|droidjack|'
            rb'ProRAT|prorat|CyberGate|cybergate|'
            rb'njw0rm|H-W0rm|Hworm|JBifrost|jbifrost|'
            rb'Adwind|adwind|AlienSpy|alienspy'
            rb')'
        ),
        "color": "#EF4444",
        "risk": "CRITICAL",
        "confidence": 93,
        "label": "C2 Framework",
        "confirmed": True,
    },
    "ddns_domain": {
        "regex": re.compile(
            rb'(?i)[a-zA-Z0-9\-]{3,63}\.(?:'
            rb'duckdns\.org|no-ip\.(?:com|biz|org|info)|'
            rb'dyndns\.(?:org|com|net)|afraid\.org|'
            rb'freedns\.afraid\.org|dynv6\.com|sytes\.net|'
            rb'myftp\.(?:biz|org)|hopto\.org|zapto\.org|ddns\.net|'
            rb'ngrok\.(?:io|app|dev)|pagekite\.me|serveo\.net|'
            rb'localhost\.run|bore\.pub|portmap\.io'
            rb')'
        ),
        "color": "#EF4444",
        "risk": "CRITICAL",
        "confidence": 96,
        "label": "Dynamic DNS / Tunnel",
        "confirmed": True,
    },
    "discord_webhook": {
        "regex": re.compile(
            rb'(?i)discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+'
        ),
        "color": "#EC4899",
        "risk": "CRITICAL",
        "confidence": 98,
        "label": "Discord Webhook",
        "confirmed": True,
    },
    "telegram_token": {
        "regex": re.compile(
            rb'(?i)(?:bot|api\.telegram\.org/bot)\d{8,10}:[a-zA-Z0-9_\-]{35,}'
        ),
        "color": "#EC4899",
        "risk": "CRITICAL",
        "confidence": 97,
        "label": "Telegram Bot Token",
        "confirmed": True,
    },
    "ngrok_tunnel": {
        "regex": re.compile(
            rb'(?i)[a-zA-Z0-9\-]+\.ngrok(?:-free)?\.(?:io|app|dev)'
        ),
        "color": "#EF4444",
        "risk": "CRITICAL",
        "confidence": 95,
        "label": "Ngrok Tunnel",
        "confirmed": True,
    },
    "tor_service": {
        "regex": re.compile(
            rb'(?i)[a-z2-7]{16,56}\.onion(?:\b|/|:)'
        ),
        "color": "#A78BFA",
        "risk": "CRITICAL",
        "confidence": 97,
        "label": "TOR Hidden Service",
        "confirmed": True,
    },

    # ── Cloud Storage ─────────────────────────────────────────────────────
    "cloud_storage": {
        "regex": re.compile(
            rb'(?i)(?:dropbox\.com|drive\.google\.com|mega\.nz|'
            rb'onedrive\.live\.com|s3\.amazonaws\.com|'
            rb'[a-z0-9\-]+\.blob\.core\.windows\.net|'
            rb'storage\.googleapis\.com|pastebin\.com|paste\.ee|'
            rb'ghostbin\.co|hastebin\.com|controlc\.com|'
            rb'transfer\.sh|file\.io|0x0\.st)'
            rb'(?:/[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]*)?' 
        ),
        "color": "#EC4899",
        "risk": "HIGH",
        "confidence": 92,
        "label": "Cloud Storage / Paste",
        "confirmed": True,
    },

    # ── System Artifacts ──────────────────────────────────────────────────
    "registry_key": {
        "regex": re.compile(
            rb'(?i)(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|'
            rb'USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)'
            rb'(?:\\[a-zA-Z0-9_\s\-\\]+)+'
        ),
        "color": "#3B82F6",
        "risk": "MEDIUM",
        "confidence": 92,
        "label": "Registry Key",
        "confirmed": True,
    },
    "windows_path": {
        "regex": re.compile(
            rb'(?i)(?:[A-Za-z]:\\|%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|'
            rb'SYSTEMROOT|WINDIR|PROGRAMFILES|PROGRAMDATA|PUBLIC|'
            rb'USERPROFILE|HOMEDRIVE|HOMEPATH)%\\?)'
            rb'(?:[a-zA-Z0-9_\-\. \\]+)+'
        ),
        "color": "#22C55E",
        "risk": "MEDIUM",
        "confidence": 85,
        "label": "Windows Path",
        "confirmed": True,
    },
    "linux_path": {
        "regex": re.compile(
            rb'(?:/(?:etc|tmp|bin|usr|var|proc|dev|sys|home|root|opt)'
            rb'(?:/[a-zA-Z0-9_\-\.]+)+)'
        ),
        "color": "#22C55E",
        "risk": "MEDIUM",
        "confidence": 75,
        "label": "Linux Path",
        "confirmed": True,
    },
    "named_pipe": {
        "regex": re.compile(
            rb'(?i)\\\\\.\\pipe\\[a-zA-Z0-9_\-\.\{\}\\]+'
        ),
        "color": "#A78BFA",
        "risk": "HIGH",
        "confidence": 88,
        "label": "Named Pipe",
        "confirmed": True,
    },
    "mutex": {
        "regex": re.compile(
            rb'(?i)(?:Global\\|Local\\|Session\\)[a-zA-Z0-9_\-\.\{\}]+'
            rb'|(?:mutex|mtx|lock)[_\-]?[a-zA-Z0-9_\-\.\{\}]{4,}'
        ),
        "color": "#A78BFA",
        "risk": "MEDIUM",
        "confidence": 80,
        "label": "Mutex Name",
        "confirmed": False,
    },

    # ── Code Execution ────────────────────────────────────────────────────
    "powershell": {
        "regex": re.compile(
            rb'(?i)(?:powershell(?:\.exe)?[\s\-]+(?:-\w+\s+)*|'
            rb'IEX\s*\(|Invoke-Expression\s*\(|'
            rb'(?:Down|Up)load(?:String|File)\s*\(|'
            rb'Net\.WebClient|'
            rb'\[System\.(?:Convert|Text|IO|Net)\]|'
            rb'FromBase64String\s*\()'
        ),
        "color": "#F97316",
        "risk": "HIGH",
        "confidence": 88,
        "label": "PowerShell Command",
        "confirmed": True,
    },
    "encoded_powershell": {
        "regex": re.compile(
            rb'(?i)powershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:enc|encodedcommand)\s+'
            rb'[A-Za-z0-9+/]+'
        ),
        "color": "#F97316",
        "risk": "CRITICAL",
        "confidence": 95,
        "label": "Encoded PowerShell",
        "confirmed": True,
    },
    "cmd_command": {
        "regex": re.compile(
            rb'(?i)(?:cmd(?:\.exe)?\s+/[cCkK]\s+|'
            rb'WScript\.Shell|'
            rb'CreateObject\s*\(\s*["\']WScript|'
            rb'shell\.exec\s*\(|'
            rb'system32\\cmd\.exe|'
            rb'certutil\s+-(?:decode|urlcache|f)|'
            rb'bitsadmin\s+/transfer|'
            rb'mshta\s+(?:https?://|vbscript:)|'
            rb'regsvr32\s+/s\s+/u\s+/i:|'
            rb'wmic\s+process\s+call\s+create)'
        ),
        "color": "#F97316",
        "risk": "HIGH",
        "confidence": 87,
        "label": "CMD / LOLBin",
        "confirmed": True,
    },

    # ── Binary Artifacts ──────────────────────────────────────────────────
    "base64_blob": {
        "regex": re.compile(
            rb'(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){12,}'
            rb'(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])'
        ),
        "color": "#EAB308",
        "risk": "MEDIUM",
        "confidence": 70,
        "label": "Base64 Blob",
        "confirmed": False,
    },
    "dll_name": {
        "regex": re.compile(
            rb'(?i)\b(?:kernel32|ntdll|user32|advapi32|ws2_32|wininet|'
            rb'winhttp|urlmon|shell32|ole32|oleaut32|comctl32|comdlg32|'
            rb'msvcrt|ucrtbase|vcruntime140|msvcp140|'
            rb'amsi|wldp|sfc|crypt32|bcrypt|ncrypt|'
            rb'psapi|wtsapi32|netapi32|secur32|wintrust|'
            rb'dbghelp|imagehlp|version|winspool)\.'
            rb'(?:dll|DLL)\b'
        ),
        "color": "#64748B",
        "risk": "LOW",
        "confidence": 95,
        "label": "DLL Import",
        "confirmed": True,
    },
    "suspicious_api": {
        "regex": re.compile(
            rb'\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|'
            rb'WriteProcessMemory|ReadProcessMemory|'
            rb'CreateRemoteThread(?:Ex)?|NtCreateThread|RtlCreateUserThread|'
            rb'SetWindowsHookEx|UnhookWindowsHookEx|'
            rb'OpenProcess|'
            rb'CreateProcess(?:A|W)?|ShellExecute(?:A|W)?|'
            rb'WinExec|'
            rb'RegSetValue(?:Ex)?[AW]?|RegCreateKey(?:Ex)?[AW]?|'
            rb'GetProcAddress|LoadLibrary(?:A|W)?|'
            rb'IsDebuggerPresent|CheckRemoteDebuggerPresent|'
            rb'NtQueryInformationProcess|OutputDebugString[AW]?|'
            rb'CryptEncrypt|CryptDecrypt|CryptAcquireContext[AW]?|'
            rb'InternetOpen[AW]?|InternetConnect[AW]?|'
            rb'HttpSendRequest[AW]?|URLDownloadToFile[AW]?|'
            rb'WSASocket|connect|send|recv|'
            rb'DeleteFile[AW]?|MoveFile(?:Ex)?[AW]?|'
            rb'SetFileAttributes[AW]?|'
            rb'AdjustTokenPrivileges|LookupPrivilegeValue[AW]?|'
            rb'CreateService[AW]?|StartService[AW]?|'
            rb'NtUnmapViewOfSection|ZwUnmapViewOfSection|'
            rb'SetThreadContext|GetThreadContext|'
            rb'QueueUserAPC|NtQueueApcThread|'
            rb'EnumProcesses|CreateToolhelp32Snapshot|'
            rb'Process32First|Process32Next)\b'
        ),
        "color": "#F59E0B",
        "risk": "MEDIUM",
        "confidence": 88,
        "label": "Suspicious API",
        "confirmed": True,
    },
    "user_agent": {
        "regex": re.compile(
            rb'(?i)(?:Mozilla/\d\.\d|'
            rb'curl/\d+\.\d+|'
            rb'python-requests/\d+\.\d+|'
            rb'Go-http-client/\d+\.\d+|'
            rb'Apache-HttpClient|'
            rb'libwww-perl|'
            rb'Wget/\d+\.\d+)\s*[\w\s\(\);\./,]+(?=[\x00-\x20\x22\x27]|$)'
        ),
        "color": "#64748B",
        "risk": "LOW",
        "confidence": 80,
        "label": "User-Agent String",
        "confirmed": False,
    },

    # ── Credentials & Secrets ─────────────────────────────────────────────
    "credential": {
        "regex": re.compile(
            rb'(?i)(?:'
            # password assignments
            rb'password\s*[=:\x00]\s*[\x22\x27]?([\w!@#$%^&*()\-+=\[\]{}|;:,.<>?/\\~`]{4,64})[\x22\x27]?|'
            rb'passwd\s*[=:\x00]\s*[\x22\x27]?([\w!@#$%^&*()\-+=]{4,64})[\x22\x27]?|'
            rb'pwd\s*[=:\x00]\s*[\x22\x27]?([\w!@#$%^&*()\-+=]{4,64})[\x22\x27]?|'
            # username/user
            rb'username\s*[=:\x00]\s*[\x22\x27]?([\w@.\-]{3,64})[\x22\x27]?|'
            rb'user\s*[=:\x00]\s*[\x22\x27]?([\w@.\-]{3,32})[\x22\x27]?|'
            # login credentials in URLs
            rb'://([\w.\-]+):([\w!@#$%^&*()\-+=]{3,64})@[a-zA-Z0-9.\-]+'
            rb')'
        ),
        "color": "#F43F5E",
        "risk": "CRITICAL",
        "confidence": 80,
        "label": "Hardcoded Credential",
        "confirmed": True,
    },
    "api_key": {
        "regex": re.compile(
            rb'(?i)(?:'
            # Generic API key / secret
            rb'api[_\-]?key\s*[=:\x00]\s*[\x22\x27]?([A-Za-z0-9_\-]{16,128})[\x22\x27]?|'
            rb'api[_\-]?secret\s*[=:\x00]\s*[\x22\x27]?([A-Za-z0-9_\-]{16,128})[\x22\x27]?|'
            rb'secret[_\-]?key\s*[=:\x00]\s*[\x22\x27]?([A-Za-z0-9_\-]{16,128})[\x22\x27]?|'
            rb'access[_\-]?token\s*[=:\x00]\s*[\x22\x27]?([A-Za-z0-9_\-\.]{16,256})[\x22\x27]?|'
            rb'auth[_\-]?token\s*[=:\x00]\s*[\x22\x27]?([A-Za-z0-9_\-\.]{16,256})[\x22\x27]?|'
            rb'bearer\s+([A-Za-z0-9_\-.]{20,512})|'
            # AWS keys
            rb'AKIA[0-9A-Z]{16}|'
            # GitHub tokens
            rb'ghp_[A-Za-z0-9]{36}|gh[ps]_[A-Za-z0-9]{36}|'
            # Stripe keys
            rb'sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|'
            # SendGrid
            rb'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}|'
            # Twilio
            rb'SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32}|'
            # Google API
            rb'AIza[0-9A-Za-z\-_]{35}'
            rb')'
        ),
        "color": "#F43F5E",
        "risk": "CRITICAL",
        "confidence": 88,
        "label": "API Key / Secret",
        "confirmed": True,
    },
    "crypto_wallet": {
        "regex": re.compile(
            rb'(?:'
            # Bitcoin (P2PKH, P2SH, Bech32)
            rb'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|'
            rb'\bbc1[a-z0-9]{6,87}\b|'
            # Ethereum
            rb'\b0x[0-9a-fA-F]{40}\b|'
            # Monero
            rb'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
            rb')'
        ),
        "color": "#F59E0B",
        "risk": "HIGH",
        "confidence": 82,
        "label": "Crypto Wallet Address",
        "confirmed": True,
    },
    "jwt_token": {
        "regex": re.compile(
            rb'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+'
        ),
        "color": "#F43F5E",
        "risk": "HIGH",
        "confidence": 90,
        "label": "JWT Token",
        "confirmed": True,
    },
    "ssh_key": {
        "regex": re.compile(
            rb'(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----|'
            rb'ssh-(?:rsa|dss|ed25519|ecdsa) AAAA[A-Za-z0-9+/]{20,})'
        ),
        "color": "#F43F5E",
        "risk": "CRITICAL",
        "confidence": 97,
        "label": "SSH Private Key",
        "confirmed": True,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _try_decode_b64(raw: bytes) -> dict | None:
    """Attempt Base64 decode and secondary-scan the result."""
    try:
        decoded = base64.b64decode(raw + b"==")
        text = decoded.decode("utf-8", errors="replace")
        secondary = {}
        if re.search(rb'https?://', decoded, re.IGNORECASE):
            secondary["contains_url"] = True
        if re.search(rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', decoded):
            secondary["contains_ip"] = True
        if re.search(rb'(?i)powershell|iex\s*\(|invoke-expression', decoded):
            secondary["contains_powershell"] = True
        if re.search(rb'(?i)cmd(?:\.exe)?\s+/[ck]', decoded):
            secondary["contains_cmd"] = True
        return {
            "decoded_preview": text[:500],
            "decoded_length": len(decoded),
            "secondary_findings": secondary,
        }
    except Exception:
        return None


def _try_decode_ps_payload(raw: bytes) -> dict | None:
    """Attempt to extract and decode -EncodedCommand payload from PowerShell string."""
    try:
        m = re.search(
            rb'(?i)-(?:enc|encodedcommand)\s+([A-Za-z0-9+/]{20,}(?:={0,2}))',
            raw
        )
        if not m:
            return None
        b64 = m.group(1)
        decoded = base64.b64decode(b64 + b"==")
        # Try UTF-16LE (common for PowerShell)
        try:
            text = decoded.decode("utf-16le")
        except Exception:
            text = decoded.decode("utf-8", errors="replace")
        return {"decoded_script": text[:1000], "decoded_length": len(decoded)}
    except Exception:
        return None


def _is_private_ip(val: str) -> bool:
    """Return True for RFC-1918 / loopback addresses."""
    parts = val.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except ValueError:
        return False


def _adjust_ip_risk(val: str, base_risk: str, base_conf: int) -> tuple[str, int]:
    if _is_private_ip(val):
        return "LOW", max(40, base_conf - 30)
    return base_risk, base_conf


def _adjust_domain_risk(val_bytes: bytes, base_risk: str, base_conf: int) -> tuple[str, int]:
    tld = val_bytes.rsplit(b".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        return "HIGH", min(95, base_conf + 15)
    return base_risk, base_conf


def _compute_overall_risk(indicators: list) -> dict:
    """Compute aggregate risk score 0-100 from all indicators."""
    if not indicators:
        return {"score": 0, "level": "CLEAN"}
    weight = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 1}
    raw = sum(weight.get(i["risk_level"], 1) * (i["confidence"] / 100) for i in indicators)
    score = min(100, int(raw))
    level = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 40 else
        "LOW" if score >= 20 else
        "INFO"
    )
    return {"score": score, "level": level}


def _make_reason(p_type: str, val: str, risk: str) -> str:
    reasons = {
        "ipv4":               f"Hardcoded IPv4 — {'external' if not _is_private_ip(val) else 'private'} address",
        "ipv6":               "Hardcoded IPv6 address",
        "ip_port":            "IP:Port pair — direct C2 server address with port",
        "url":                "Hardcoded URL — possible download/C2 endpoint",
        "domain":             "Embedded domain name — possible C2 or exfil target",
        "email":              "Embedded email — possible exfil or contact address",
        "c2_endpoint":        "C2 beacon/gate endpoint detected — high-confidence C2",
        "c2_framework":       "Known C2/RAT framework string — malware family identified",
        "ddns_domain":        "Dynamic DNS domain — common attacker infrastructure to hide real IP",
        "discord_webhook":    "Discord Webhook — common data exfil via Discord",
        "telegram_token":     "Telegram Bot Token — common C2/exfil channel",
        "cloud_storage":      "Cloud storage link — possible payload host or exfil",
        "registry_key":       "Windows Registry path — persistence or config storage",
        "windows_path":       "Hardcoded Windows file path — possible drop location",
        "linux_path":         "Hardcoded Linux path — possible drop or persistence",
        "named_pipe":         "Named pipe — inter-process communication or lateral movement",
        "mutex":              "Mutex name — used to prevent multiple malware instances",
        "powershell":         "PowerShell execution — common malware tradecraft",
        "encoded_powershell": "Encoded PowerShell — obfuscated execution, high risk",
        "cmd_command":        "CMD execution string — shell command embedded",
        "base64_blob":        "Base64 blob — possible obfuscated payload or config",
        "dll_name":           "DLL import name — indicates imported library",
        "suspicious_api":     "Suspicious Win32 API — common malware function",
        "user_agent":         "Browser User-Agent string — HTTP client fingerprint",
        "ngrok_tunnel":       "Ngrok tunnel URL — used to expose local C2 servers",
        "tor_service":        "TOR hidden service — high-anonymity C2 infrastructure",
        "credential":         "Hardcoded credential (username/password) — immediate risk",
        "api_key":            "Hardcoded API key or secret token — revoke immediately",
        "crypto_wallet":      "Cryptocurrency wallet address — financial theft or cryptominer",
        "jwt_token":          "JSON Web Token — stolen auth token, may grant system access",
        "ssh_key":            "SSH private key material — critical credential exposure",
    }
    return reasons.get(p_type, f"Matches known {p_type} pattern")


# ─────────────────────────────────────────────────────────────────────────────
#  IOC EXPORT FORMATTERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_ioc_groups(indicators: list) -> dict:
    groups: dict[str, list] = {}
    for ind in indicators:
        cat = ind["type"]
        groups.setdefault(cat, [])
        if ind["value"] not in groups[cat]:
            groups[cat].append(ind["value"])
    return groups


def _export_json(sample: Sample, indicators: list) -> bytes:
    groups = _build_ioc_groups(indicators)
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "id": sample.id,
            "filename": sample.filename,
            "md5": sample.md5,
            "sha256": sample.sha256,
        },
        "iocs": groups,
        "indicators": indicators[:500],
        "total": len(indicators),
    }
    return json.dumps(payload, indent=2).encode()


def _export_csv(sample: Sample, indicators: list) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "offset_hex", "risk_level", "confidence", "label",
                "confirmed", "mitre_ids", "reason"])
    for ind in indicators:
        mitre_ids = "|".join(m["id"] for m in ind.get("mitre", []))
        w.writerow([
            ind["type"], ind["value"],
            f"0x{ind['offset']:08X}",
            ind["risk_level"], ind["confidence"], ind["label"],
            ind.get("confirmed", False), mitre_ids,
            ind.get("reason", ""),
        ])
    return buf.getvalue().encode()


def _export_txt(sample: Sample, indicators: list) -> bytes:
    lines = [
        "# CyberForge Hex IOC Export v2.0",
        f"# Sample  : {sample.filename}",
        f"# SHA-256 : {sample.sha256 or 'N/A'}",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    groups = _build_ioc_groups(indicators)
    for cat, vals in groups.items():
        lines.append(f"[{cat.upper()}]")
        lines.extend(vals)
        lines.append("")
    return "\n".join(lines).encode()


def _export_stix(sample: Sample, indicators: list) -> bytes:
    """Minimal STIX 2.1 JSON bundle."""
    bundle_id = f"bundle--{sample.id}"
    objects = []
    for ind in indicators[:500]:
        mitre_refs = [m["id"] for m in ind.get("mitre", [])]
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{sample.id}-{ind['offset']}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": ind["label"],
            "description": ind.get("reason", ""),
            "pattern": f"[file:content MATCHES '{re.escape(ind['value'])}']",
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "labels": [ind["type"]],
            "confidence": ind["confidence"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": mid}
                for mid in mitre_refs
            ],
            "extensions": {
                "x-cyberforge": {
                    "risk_level": ind["risk_level"],
                    "offset_hex": f"0x{ind['offset']:08X}",
                    "color": ind.get("color", "#94A3B8"),
                    "confirmed": ind.get("confirmed", False),
                }
            },
        }
        objects.append(obj)
    bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
    return json.dumps(bundle, indent=2).encode()


def _export_openioc(sample: Sample, indicators: list) -> bytes:
    """OpenIOC 1.1 XML export."""
    ioc = ET.Element("ioc", {
        "xmlns": "http://schemas.mandiant.com/2010/ioc",
        "id": sample.id,
        "created-on": datetime.now(timezone.utc).isoformat(),
    })
    ET.SubElement(ioc, "short_description").text = f"CyberForge: {sample.filename}"
    ET.SubElement(ioc, "authored_by").text = "CyberForge Hex Analyzer v2.0"
    ET.SubElement(ioc, "authored_date").text = datetime.now(timezone.utc).isoformat()
    definition = ET.SubElement(ioc, "definition")
    indicator = ET.SubElement(definition, "Indicator", {"operator": "OR", "id": f"{sample.id}-root"})
    for ind in indicators[:500]:
        item = ET.SubElement(indicator, "IndicatorItem", {
            "id": f"{sample.id}-{ind['offset']}",
            "condition": "contains",
        })
        ET.SubElement(item, "Context", {
            "document": "FileItem",
            "search": "FileItem/FileContents",
            "type": "mir",
        })
        content = ET.SubElement(item, "Content", {"type": "string"})
        content.text = ind["value"]
    return ET.tostring(ioc, encoding="utf-8", xml_declaration=True)


def _export_yara(sample: Sample, indicators: list) -> bytes:
    """Generate a YARA rule from detected indicators."""
    fn_safe = re.sub(r'[^a-zA-Z0-9_]', '_', sample.filename.rsplit('.', 1)[0])
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f'rule CyberForge_{fn_safe} {{',
        f'    meta:',
        f'        description = "Auto-generated by CyberForge Hex Analyzer"',
        f'        author = "CyberForge"',
        f'        date = "{ts}"',
        f'        sha256 = "{sample.sha256 or "unknown"}"',
        f'        filename = "{sample.filename}"',
        f'',
        f'    strings:',
    ]

    seen: set[str] = set()
    str_count = 0
    MAX_STRINGS = 50

    # Prioritise high-risk indicators
    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_inds = sorted(indicators, key=lambda x: priority.get(x["risk_level"], 4))

    for ind in sorted_inds:
        if str_count >= MAX_STRINGS:
            break
        val = ind["value"].strip()
        if not val or val in seen or len(val) < 4:
            continue
        if any(c in val for c in ['"', '\\']):
            # Use hex encoding for tricky strings
            hex_str = " ".join(f"{b:02X}" for b in val.encode("utf-8", errors="replace"))
            var_name = f"$s{str_count}"
            lines.append(f'        {var_name} = {{ {hex_str} }}  // {ind["label"]} @ 0x{ind["offset"]:08X}')
        else:
            var_name = f"$s{str_count}"
            # Limit string length
            yara_val = val[:200]
            lines.append(f'        {var_name} = "{yara_val}" nocase  // {ind["label"]} @ 0x{ind["offset"]:08X}')
        seen.add(val)
        str_count += 1

    if str_count == 0:
        lines.append('        $dummy = "CyberForge_no_strings"')

    condition_vars = " or ".join(f"$s{i}" for i in range(str_count)) if str_count > 0 else "$dummy"

    lines += [
        f'',
        f'    condition:',
        f'        {condition_vars}',
        f'}}',
    ]

    header = [
        f'// CyberForge YARA Rule Export',
        f'// Generated: {ts}',
        f'// Sample: {sample.filename}',
        f'// SHA-256: {sample.sha256 or "unknown"}',
        f'// Total indicators: {len(indicators)}',
        f'',
    ]
    return "\n".join(header + lines).encode()


def _export_sigma(sample: Sample, indicators: list) -> bytes:
    """Generate a Sigma rule from detected indicators."""
    fn_safe = re.sub(r'[^a-zA-Z0-9_]', '_', sample.filename.rsplit('.', 1)[0])
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # Collect strings for detection
    cmd_strings = []
    net_strings = []

    for ind in indicators[:100]:
        val = ind["value"].strip()
        if not val or len(val) < 4:
            continue
        if ind["type"] in ("powershell", "encoded_powershell", "cmd_command"):
            cmd_strings.append(f'        - "{val[:120]}"')
        elif ind["type"] in ("url", "domain", "ipv4", "c2_endpoint"):
            net_strings.append(f'        - "{val[:120]}"')

    sigma_lines = [
        f"title: CyberForge - {sample.filename} IOC Detection",
        f"id: cyberforge-{sample.id[:8] if sample.id else 'unknown'}",
        f"status: experimental",
        f"description: Auto-generated Sigma rule from CyberForge hex analysis of {sample.filename}",
        f"author: CyberForge Hex Analyzer",
        f"date: {ts}",
        f"tags:",
    ]

    # Add MITRE tags
    mitre_seen: set[str] = set()
    for ind in indicators[:50]:
        for m in ind.get("mitre", []):
            tid = m["id"].lower().replace(".", "-")
            tag = f"attack.{tid}"
            if tag not in mitre_seen:
                sigma_lines.append(f"    - {tag}")
                mitre_seen.add(tag)
                if len(mitre_seen) >= 10:
                    break

    sigma_lines += [
        f"logsource:",
        f"    category: process_creation",
        f"    product: windows",
        f"detection:",
    ]

    if cmd_strings:
        sigma_lines.append("    cmd_indicators:")
        sigma_lines.append("        CommandLine|contains:")
        sigma_lines.extend(cmd_strings[:20])

    if net_strings:
        sigma_lines.append("    net_indicators:")
        sigma_lines.append("        DestinationHostname|contains:")
        sigma_lines.extend(net_strings[:20])

    if not cmd_strings and not net_strings:
        sigma_lines += [
            "    selection:",
            f"        Image|contains: '{sample.filename}'",
        ]
        condition = "selection"
    else:
        parts = []
        if cmd_strings:
            parts.append("cmd_indicators")
        if net_strings:
            parts.append("net_indicators")
        condition = " or ".join(parts)

    sigma_lines += [
        f"    condition: {condition}",
        f"falsepositives:",
        f"    - Legitimate software using similar patterns",
        f"level: high",
        f"",
        f"# Generated by CyberForge Hex Analyzer",
        f"# Sample SHA-256: {sample.sha256 or 'unknown'}",
        f"# Total IOCs detected: {len(indicators)}",
    ]

    return "\n".join(sigma_lines).encode()


# ─────────────────────────────────────────────────────────────────────────────
#  PE SECTION PARSER (lightweight, no pefile dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_pe_sections(data: bytes) -> list[dict]:
    """Parse PE section table. Returns list of {name, vaddr, vsize, roffset, rsize}."""
    sections = []
    try:
        if len(data) < 64 or data[:2] != b'MZ':
            return sections

        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return sections

        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b'PE\x00\x00':
            return sections

        machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        opt_header_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]

        section_table_offset = e_lfanew + 24 + opt_header_size

        for i in range(min(num_sections, 96)):
            off = section_table_offset + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8].rstrip(b'\x00')
            try:
                name = name_raw.decode('ascii', errors='replace')
            except Exception:
                name = '.unk'
            vsize   = struct.unpack_from('<I', data, off + 16)[0]
            vaddr   = struct.unpack_from('<I', data, off + 12)[0]
            rsize   = struct.unpack_from('<I', data, off + 20)[0] if off + 24 <= len(data) else 0
            roffset = struct.unpack_from('<I', data, off + 20)[0] if off + 24 <= len(data) else 0
            # offset+16 = VirtualSize, offset+12 = VirtualAddress
            # offset+20 = SizeOfRawData, offset+24 = PointerToRawData
            vsize   = struct.unpack_from('<I', data, off + 8)[0]   # VirtualSize
            vaddr   = struct.unpack_from('<I', data, off + 12)[0]  # VirtualAddress
            rsize   = struct.unpack_from('<I', data, off + 16)[0]  # SizeOfRawData
            roffset = struct.unpack_from('<I', data, off + 20)[0]  # PointerToRawData

            sections.append({
                "name": name,
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_offset": roffset,
                "raw_size": rsize,
            })
    except Exception:
        pass
    return sections


def _offset_to_section(offset: int, sections: list[dict]) -> str:
    """Given a raw file offset, find which PE section it belongs to."""
    for sec in sections:
        start = sec["raw_offset"]
        end   = start + sec["raw_size"]
        if start <= offset < end:
            return sec["name"] or ".unk"
    return "header" if offset < 4096 else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  FULL SCAN HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _run_full_scan(path: Path, sections: list[dict]) -> list[dict]:
    """Run pattern scan on the entire file, returning enriched indicator list."""
    results: list[dict] = []
    seen_values: set[str] = set()

    CHUNK_SIZE = 10 * 1024 * 1024
    OVERLAP    = 2048

    with open(path, "rb") as f:
        file_offset = 0
        while True:
            chunk = f.read(CHUNK_SIZE + OVERLAP)
            if not chunk:
                break

            for p_type, cfg in PATTERNS.items():
                for match in cfg["regex"].finditer(chunk):
                    raw = match.group()
                    try:
                        val = raw.decode("utf-8", errors="replace").strip()
                    except Exception:
                        continue

                    if not val or val in seen_values:
                        continue

                    # Domain noise filter
                    if p_type == "domain":
                        if len(val) < 7 or "." not in val:
                            continue
                        if any(val in r["value"] for r in results[-20:]):
                            continue

                    # IPv4 noise filter — only skip garbage values
                    if p_type == "ipv4":
                        parts = val.split(".")
                        # Skip obvious version numbers: 1.0.0.0, 6.2.9200.0
                        if all(p in ("0","1","2","3","4","5","255") for p in parts):
                            continue
                        try:
                            octets = [int(p) for p in parts]
                            # Skip version-number pattern: low.low.0.0
                            if octets[0] <= 9 and octets[1] <= 9 and octets[2] == 0 and octets[3] == 0:
                                continue
                            # Skip pure broadcast / loopback
                            if octets[0] == 0 or octets[0] == 127 or octets[0] == 255:
                                continue
                        except ValueError:
                            continue

                    # credential noise filter — skip very short or common placeholder values
                    if p_type == "credential":
                        lower_val = val.lower()
                        skip_creds = {"password", "passwd", "secret", "changeme", "yourpassword",
                                      "admin", "123456", "test", "user", "root", "<password>",
                                      "[password]", "{password}", "pass", "pwd", "xxxx", "****"}
                        if lower_val in skip_creds or len(val) < 4:
                            continue

                    seen_values.add(val)

                    risk = cfg["risk"]
                    conf = cfg["confidence"]
                    extra: dict = {}

                    if p_type == "ipv4":
                        risk, conf = _adjust_ip_risk(val, risk, conf)
                        # Private IPs reported with lower risk
                        if _is_private_ip(val):
                            risk = "MEDIUM"
                            conf = max(40, conf - 20)
                    elif p_type == "domain":
                        risk, conf = _adjust_domain_risk(raw, risk, conf)
                    elif p_type == "base64_blob":
                        b64_info = _try_decode_b64(raw)
                        if b64_info:
                            sf = b64_info.get("secondary_findings", {})
                            if sf.get("contains_powershell") or sf.get("contains_cmd"):
                                risk = "CRITICAL"
                                conf = 93
                            elif sf.get("contains_url") or sf.get("contains_ip"):
                                risk = "HIGH"
                                conf = 85
                            extra["base64_decoded"] = b64_info
                    elif p_type == "encoded_powershell":
                        ps_info = _try_decode_ps_payload(raw)
                        if ps_info:
                            extra["powershell_decoded"] = ps_info

                    actual_offset = file_offset + match.start()

                    entry: dict = {
                        "offset": actual_offset,
                        "length": len(raw),
                        "type": p_type,
                        "value": val[:512],
                        "risk_level": risk,
                        "confidence": conf,
                        "color": cfg["color"],
                        "label": cfg["label"],
                        "reason": _make_reason(p_type, val, risk),
                        "confirmed": cfg.get("confirmed", False),
                        "mitre": MITRE_MAP.get(p_type, []),
                        "recommended_action": ACTIONS.get(p_type, ""),
                        "section": _offset_to_section(actual_offset, sections),
                    }
                    entry.update(extra)

                    results.append(entry)

                    if len(results) >= 2000:
                        break
                if len(results) >= 2000:
                    break

            if len(chunk) <= CHUNK_SIZE:
                break

            file_offset += CHUNK_SIZE
            f.seek(file_offset)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    results.sort(key=lambda x: (order.get(x["risk_level"], 5), x["offset"]))
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{sample_id}/hex")
def get_hex_chunk(
    sample_id: str,
    offset: int = 0,
    size: int = 4096,
    db: Session = Depends(get_db),
):
    """Fetch a specific chunk of the binary file as Base64 (virtual scrolling)."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    total_size = path.stat().st_size
    if offset >= total_size:
        return {"data": "", "offset": offset, "size": 0, "total_size": total_size}

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(min(size, 65536))

    return {
        "data": base64.b64encode(data).decode("utf-8"),
        "offset": offset,
        "size": len(data),
        "total_size": total_size,
    }


@router.get("/{sample_id}/hex/stats")
def get_hex_stats(
    sample_id: str,
    offset: int = 0,
    size: int = 65536,
    db: Session = Depends(get_db),
):
    """
    Return byte frequency statistics for a chunk.
    Used by the Byte Statistics panel in the frontend.
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    total_size = path.stat().st_size
    actual_size = min(size, 524288)  # cap at 512KB

    with open(path, "rb") as f:
        f.seek(max(0, offset))
        data = f.read(actual_size)

    if not data:
        return {"frequencies": [], "entropy": 0.0, "total_bytes": 0}

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    # Shannon entropy
    import math
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    # Top 32 bytes
    top = sorted(
        [{"byte": i, "hex": f"{i:02X}", "count": freq[i], "percent": round(freq[i] / total * 100, 2)}
         for i in range(256)],
        key=lambda x: -x["count"]
    )[:32]

    return {
        "frequencies": top,
        "all_frequencies": freq,
        "entropy": round(entropy, 4),
        "total_bytes": total,
        "offset": offset,
    }


@router.get("/{sample_id}/hex/pe-sections")
def get_pe_sections(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """
    Parse and return PE section table for the sample.
    Returns section names, virtual addresses, and raw file offsets.
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    # Read first 512KB for PE header + section table
    with open(path, "rb") as f:
        header_data = f.read(min(524288, path.stat().st_size))

    sections = _parse_pe_sections(header_data)
    return {"sections": sections, "is_pe": bool(sections)}


@router.post("/{sample_id}/hex/analyze")
def analyze_hex_artifacts(sample_id: str, db: Session = Depends(get_db)):
    """
    Scan the entire binary for forensic artifacts.
    Returns categorized indicators with MITRE ATT&CK mapping, AI risk scoring,
    confidence levels, PE section context, and recommended actions.
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    # Parse PE sections for context
    with open(path, "rb") as f:
        header_data = f.read(min(524288, path.stat().st_size))
    sections = _parse_pe_sections(header_data)

    results = _run_full_scan(path, sections)
    overall = _compute_overall_risk(results)

    # Build IOC summary
    ioc_summary: dict[str, list] = {}
    for ind in results:
        ioc_summary.setdefault(ind["type"], [])
        if ind["value"] not in ioc_summary[ind["type"]]:
            ioc_summary[ind["type"]].append(ind["value"])

    return {
        "indicators": results[:1500],
        "total_found": len(results),
        "overall_risk": overall,
        "scan_patterns": list(PATTERNS.keys()),
        "ioc_summary": ioc_summary,
        "sections": sections,
        "mitre_coverage": list({
            tid
            for ind in results
            for m in ind.get("mitre", [])
            for tid in [m["id"]]
        }),
    }


@router.post("/{sample_id}/hex/search")
def search_hex(
    sample_id: str,
    req: HexSearchRequest,
    db: Session = Depends(get_db),
):
    """Search for arbitrary bytes or strings in the binary (ASCII / Hex / Unicode)."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    try:
        if req.search_type == "hex":
            query_bytes = bytes.fromhex(req.query.replace(" ", "").replace(":", ""))
        elif req.search_type == "ascii":
            query_bytes = req.query.encode("ascii", errors="replace")
        elif req.search_type == "unicode":
            query_bytes = req.query.encode("utf-16le")
        else:
            raise HTTPException(400, "Invalid search type — use hex, ascii, or unicode")
    except (ValueError, UnicodeEncodeError) as e:
        raise HTTPException(400, f"Invalid search query: {e}")

    if not query_bytes:
        return {"offsets": [], "count": 0}

    offsets: list[int] = []
    CHUNK_SIZE = 10 * 1024 * 1024
    overlap = max(0, len(query_bytes) - 1)

    with open(path, "rb") as f:
        file_offset = 0
        while True:
            chunk = f.read(CHUNK_SIZE + overlap)
            if not chunk:
                break

            idx = 0
            while True:
                idx = chunk.find(query_bytes, idx)
                if idx == -1:
                    break
                if idx < CHUNK_SIZE or len(chunk) <= CHUNK_SIZE:
                    offsets.append(file_offset + idx)
                idx += 1
                if len(offsets) >= 500:
                    break

            if len(offsets) >= 500 or len(chunk) <= CHUNK_SIZE:
                break

            file_offset += CHUNK_SIZE
            f.seek(file_offset)

    return {"offsets": offsets, "count": len(offsets)}


# ─────────────────────────────────────────────────────────────────────────────
#  STRINGS EXTRACTOR  (like `strings` command — ASCII + UTF-16LE)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_strings(
    path: Path,
    min_len: int = 4,
    max_strings: int = 5000,
    encoding: str = "both",   # "ascii" | "utf16" | "both"
    filter_query: str = "",
) -> list[dict]:
    """
    Extract human-readable strings from a binary file.
    Supports ASCII (printable 0x20–0x7E) and UTF-16LE (wide) strings.
    Returns list of {offset, length, value, encoding, category}.
    """

    PRINTABLE = set(range(0x20, 0x7F))   # space … ~
    PRINTABLE.add(0x09)  # tab
    PRINTABLE.add(0x0A)  # newline
    PRINTABLE.add(0x0D)  # carriage return

    strings: list[dict] = []
    filter_lower = filter_query.lower() if filter_query else ""

    def _categorize(val: str) -> str:
        v = val.lower()
        if re.search(r'https?://', v):
            return "url"
        if re.search(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', v):
            return "ip"
        if re.search(r'[a-z0-9._-]+\.[a-z]{2,}$', v) and '.' in v and len(v) > 5:
            return "domain"
        if re.search(r'(?:hkey|hklm|hkcu|hkcr)', v):
            return "registry"
        if re.search(r'(?:[a-z]:\\|%appdata%|%temp%|%systemroot%)', v):
            return "path"
        if re.search(r'(?:powershell|iex|invoke-expression|encodedcommand)', v):
            return "powershell"
        if re.search(r'(?:virtualalloc|writeprocessmemory|createremotethread|loadlibrary)', v):
            return "api"
        if re.search(r'(?:\.dll|\.exe|\.sys|\.drv)$', v):
            return "binary"
        if re.search(r'(?:password|passwd|secret|apikey|token|auth)', v):
            return "credential"
        if re.search(r'(?:[a-zA-Z0-9+/]{40,}={0,2})', v):
            return "base64"
        if re.search(r'(?:select |insert |update |delete |from |where )', v):
            return "sql"
        if re.search(r'^[A-Za-z0-9+/\-_]{20,}$', v):
            return "encoded"
        return "string"

    # ── Read file in 64 MB chunks (constant RAM even for 500 MB files) ──
    CHUNK_SIZE = 64 * 1024 * 1024   # 64 MB per pass
    OVERLAP    = 4096               # bytes carried over between chunks
    #   The overlap ensures strings that span a chunk boundary are not missed.

    file_size = path.stat().st_size
    file_offset = 0

    # We'll accumulate results across chunks then deduplicate / sort at end
    with open(path, "rb") as f:
        carry = b""  # leftover bytes from previous chunk (for overlap)

        while file_offset < file_size and len(strings) < max_strings:
            f.seek(file_offset)
            raw_chunk = f.read(CHUNK_SIZE)
            if not raw_chunk:
                break

            # Prepend carry-over so boundary strings aren't missed
            chunk = carry + raw_chunk
            carry_offset = file_offset - len(carry)   # real file offset of chunk[0]

            # ── ASCII pass ──────────────────────────────────────────────
            if encoding in ("ascii", "both"):
                i = 0
                chunk_len = len(chunk)
                while i < chunk_len and len(strings) < max_strings:
                    if chunk[i] in PRINTABLE:
                        j = i
                        while j < chunk_len and chunk[j] in PRINTABLE:
                            j += 1
                        segment = chunk[i:j]
                        if len(segment) >= min_len:
                            abs_off = carry_offset + i
                            # Only emit if this segment started in the new chunk
                            # (carry bytes would generate duplicate entries otherwise)
                            if abs_off >= file_offset or file_offset == 0:
                                try:
                                    val = segment.decode("utf-8", errors="replace").rstrip()
                                    if not filter_lower or filter_lower in val.lower():
                                        strings.append({
                                            "offset": abs_off,
                                            "length": len(segment),
                                            "value": val[:512],
                                            "encoding": "ASCII",
                                            "category": _categorize(val),
                                        })
                                except Exception:
                                    pass
                        i = j + 1
                    else:
                        i += 1

            # ── UTF-16LE (wide string) pass ─────────────────────────────
            if encoding in ("utf16", "both") and len(strings) < max_strings:
                i = 0
                chunk_len = len(chunk)
                while i < chunk_len - 1 and len(strings) < max_strings:
                    if chunk[i] in PRINTABLE and i + 1 < chunk_len and chunk[i + 1] == 0x00:
                        j = i
                        while j + 1 < chunk_len and chunk[j] in PRINTABLE and chunk[j + 1] == 0x00:
                            j += 2
                        segment = chunk[i:j]
                        char_count = len(segment) // 2
                        if char_count >= min_len:
                            abs_off = carry_offset + i
                            if abs_off >= file_offset or file_offset == 0:
                                try:
                                    val = segment.decode("utf-16le", errors="replace").rstrip('\x00').rstrip()
                                    if not filter_lower or filter_lower in val.lower():
                                        already = any(
                                            abs(s["offset"] - abs_off) < 4 and s["value"] == val
                                            for s in strings[-20:]
                                        )
                                        if not already:
                                            strings.append({
                                                "offset": abs_off,
                                                "length": len(segment),
                                                "value": val[:512],
                                                "encoding": "UTF-16LE",
                                                "category": _categorize(val),
                                            })
                                except Exception:
                                    pass
                        i = j + 2
                    else:
                        i += 1

            # Advance: keep last OVERLAP bytes as carry for next iteration
            carry = raw_chunk[-OVERLAP:] if len(raw_chunk) > OVERLAP else raw_chunk
            file_offset += len(raw_chunk)

    # Sort by offset
    strings.sort(key=lambda x: x["offset"])
    return strings[:max_strings]


@router.get("/{sample_id}/hex/strings")
def get_hex_strings(
    sample_id: str,
    min_len: int = Query(4, ge=1, le=200),
    encoding: str = Query("both", regex="^(ascii|utf16|both)$"),
    category: str = Query("all"),
    search: str = Query(""),
    offset_start: int = Query(0, ge=0),
    offset_end: int = Query(0, ge=0),   # 0 = no limit
    limit: int = Query(2000, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    """
    Extract and return all printable strings from the binary (like the `strings` command).
    Supports ASCII and UTF-16LE (wide strings), with search, category filter,
    min-length filter, and offset range filtering.
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    all_strings = _extract_strings(
        path,
        min_len=min_len,
        max_strings=limit * 3,   # over-fetch to allow filtering
        encoding=encoding,
        filter_query=search,
    )

    # Category filter
    if category and category != "all":
        all_strings = [s for s in all_strings if s["category"] == category]

    # Offset range filter
    if offset_end > 0:
        all_strings = [
            s for s in all_strings
            if offset_start <= s["offset"] <= offset_end
        ]
    elif offset_start > 0:
        all_strings = [s for s in all_strings if s["offset"] >= offset_start]

    total = len(all_strings)
    result = all_strings[:limit]

    # Compute category summary
    cat_counts: dict[str, int] = {}
    for s in all_strings:
        cat_counts[s["category"]] = cat_counts.get(s["category"], 0) + 1

    return {
        "strings": result,
        "total": total,
        "returned": len(result),
        "category_counts": cat_counts,
        "file_size": path.stat().st_size,
    }


@router.get("/{sample_id}/hex/iocs")
def export_hex_iocs(
    sample_id: str,
    format: str = Query("json", regex="^(json|csv|txt|stix|openioc|yara|sigma)$"),
    db: Session = Depends(get_db),
):
    """
    Export all detected IOCs from the hex analysis in various formats.
    Supported: json, csv, txt, stix, openioc, yara, sigma
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    path = Path(sample.storage_path)
    if not path.exists():
        raise HTTPException(404, "File not found on disk")

    # Parse PE sections
    with open(path, "rb") as f:
        header_data = f.read(min(524288, path.stat().st_size))
    sections = _parse_pe_sections(header_data)

    results = _run_full_scan(path, sections)

    fn_base = sample.filename.rsplit(".", 1)[0]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    format_map = {
        "json":    (_export_json,    "application/json",       f"{fn_base}_iocs_{ts}.json"),
        "csv":     (_export_csv,     "text/csv",               f"{fn_base}_iocs_{ts}.csv"),
        "txt":     (_export_txt,     "text/plain",             f"{fn_base}_iocs_{ts}.txt"),
        "stix":    (_export_stix,    "application/json",       f"{fn_base}_iocs_{ts}.stix.json"),
        "openioc": (_export_openioc, "application/xml",        f"{fn_base}_iocs_{ts}.ioc"),
        "yara":    (_export_yara,    "text/plain",             f"{fn_base}_{ts}.yar"),
        "sigma":   (_export_sigma,   "text/plain",             f"{fn_base}_{ts}.yml"),
    }

    fn, ct, fname = format_map[format]
    data = fn(sample, results)

    return Response(
        content=data,
        media_type=ct,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
