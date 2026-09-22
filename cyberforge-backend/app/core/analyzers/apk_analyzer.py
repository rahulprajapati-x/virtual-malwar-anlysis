import logging
from pathlib import Path

logger = logging.getLogger("cyberforge.analyzers.apk")

def analyze_apk(file_path: Path) -> dict:
    result = {
        "is_apk": False,
        "package_name": "",
        "version_name": "",
        "permissions": [],
        "main_activity": "",
        "services": [],
        "receivers": []
    }
    
    if file_path.suffix.lower() != '.apk':
        return result
        
    try:
        from pyaxmlparser import APK
    except ImportError:
        logger.warning("pyaxmlparser not installed, skipping deep APK analysis")
        return result

    try:
        apk = APK(str(file_path))
        result["is_apk"] = True
        result["package_name"] = apk.package
        result["version_name"] = apk.version_name
        result["permissions"] = apk.get_permissions()
        result["main_activity"] = apk.get_main_activity()
        result["services"] = apk.get_services()
        result["receivers"] = apk.get_receivers()
    except Exception as e:
        logger.error(f"APK analysis failed: {e}")
        
    return result
