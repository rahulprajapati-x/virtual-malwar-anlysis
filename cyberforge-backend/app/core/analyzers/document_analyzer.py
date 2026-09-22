import logging
from pathlib import Path

logger = logging.getLogger("cyberforge.analyzers.document")

def analyze_document(file_path: Path) -> dict:
    result = {
        "is_document": False,
        "has_macros": False,
        "macro_code": [],
        "suspicious_indicators": [],
        "ole_format": False
    }
    
    try:
        from oletools.olevba import VBA_Parser
        from oletools.oleid import OleID
    except ImportError:
        logger.warning("oletools not installed, skipping deep document analysis")
        return result

    try:
        # Check if it's an OLE/OpenXML file
        oid = OleID(str(file_path))
        indicators = oid.check()
        result["is_document"] = True
        
        for ind in indicators:
            if ind.value and ind.id in ['vba_macros', 'flash', 'encrypted', 'object_pool']:
                if ind.value is True or (isinstance(ind.value, int) and ind.value > 0):
                    result["suspicious_indicators"].append({
                        "name": ind.name,
                        "description": ind.description
                    })
            if ind.id == 'format':
                result["ole_format"] = (ind.value == 'OLE')
                
        # Parse VBA macros
        vba = VBA_Parser(str(file_path))
        if vba.detect_vba_macros():
            result["has_macros"] = True
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                result["macro_code"].append({
                    "stream_path": stream_path,
                    "vba_filename": vba_filename,
                    "code_snippet": vba_code[:1000] # First 1000 chars to avoid massive DB bloat
                })
        vba.close()
    except Exception as e:
        logger.error(f"Document analysis failed: {e}")
        
    return result
