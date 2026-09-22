import logging
from pathlib import Path

logger = logging.getLogger("cyberforge.analyzers.structural")

def analyze_structure(file_path: Path) -> dict:
    result = {
        "anomalies": [],
        "is_valid_pe": False,
        "warnings": 0
    }
    
    try:
        import pefile
        pe = pefile.PE(str(file_path))
        result["is_valid_pe"] = True
        
        # Check overlapping sections
        sections = pe.sections
        for i in range(len(sections) - 1):
            s1 = sections[i]
            s2 = sections[i+1]
            s1_end = s1.VirtualAddress + s1.Misc_VirtualSize
            if s1_end > s2.VirtualAddress and s1.VirtualAddress < s2.VirtualAddress:
                result["anomalies"].append(f"Overlapping sections detected: {s1.Name.decode('utf-8', 'ignore').strip(chr(0))} and {s2.Name.decode('utf-8', 'ignore').strip(chr(0))}")
                result["warnings"] += 1
                
        # Check for abnormal section count
        if len(sections) > 10 or len(sections) == 0:
            result["anomalies"].append(f"Abnormal number of sections: {len(sections)}")
            result["warnings"] += 1
            
        # Check entry point out of bounds
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_valid = False
        for s in sections:
            if s.VirtualAddress <= ep < (s.VirtualAddress + s.Misc_VirtualSize):
                ep_valid = True
                break
        if not ep_valid:
            result["anomalies"].append("Entry point points outside of valid sections")
            result["warnings"] += 1
            
        pe.close()
    except Exception as e:
        # Not a PE file or corrupted
        pass
        
    return result
