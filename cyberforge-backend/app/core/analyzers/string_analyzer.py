import re
from pathlib import Path

# Common patterns
URL_PATTERN = re.compile(rb'https?://[a-zA-Z0-9./\-_?&=]+')
PATH_PATTERN = re.compile(rb'[A-Za-z]:\\[\\[A-Za-z0-9_\-\\]+\.[A-Za-z]+')
REG_PATTERN = re.compile(rb'(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\-\\]+')
B64_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
API_PATTERN = re.compile(rb'(VirtualAlloc|CreateProcess|WriteProcessMemory|LoadLibrary|GetProcAddress|InternetOpen|URLDownloadToFile)')

def extract_and_classify_strings(file_path: Path) -> dict:
    strings = []
    categorized = {
        "urls": [],
        "paths": [],
        "registry": [],
        "base64": [],
        "suspicious_apis": []
    }
    
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        # Basic ASCII string extraction
        ascii_strings = re.findall(rb'[ -~]{5,}', data)
        # Basic Unicode string extraction (UTF-16LE)
        unicode_strings = re.findall(rb'(?:[\x20-\x7E]\x00){5,}', data)
        
        for s in ascii_strings + [u.replace(b'\x00', b'') for u in unicode_strings]:
            if URL_PATTERN.search(s):
                categorized["urls"].append(s.decode('utf-8', 'ignore'))
            elif PATH_PATTERN.search(s):
                categorized["paths"].append(s.decode('utf-8', 'ignore'))
            elif REG_PATTERN.search(s):
                categorized["registry"].append(s.decode('utf-8', 'ignore'))
            elif B64_PATTERN.search(s):
                categorized["base64"].append(s.decode('utf-8', 'ignore'))
            elif API_PATTERN.search(s):
                categorized["suspicious_apis"].append(s.decode('utf-8', 'ignore'))
                
        # Deduplicate
        for k in categorized:
            categorized[k] = list(set(categorized[k]))
            
        return {
            "total_strings_extracted": len(ascii_strings) + len(unicode_strings),
            "categorized": categorized
        }
    except Exception as e:
        return {
            "total_strings_extracted": 0,
            "categorized": {},
            "error": str(e)
        }
