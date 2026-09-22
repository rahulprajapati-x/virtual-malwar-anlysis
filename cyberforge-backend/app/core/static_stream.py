import time
import asyncio
import logging
from pathlib import Path
from typing import Optional, AsyncGenerator

from app.core.static_analyzer import (
    AnalysisReport, compute_hashes, _detect_mime, parse_pe, extract_iocs, map_to_attack, _score_to_level, _EXT_BASE_RISK
)
from app.core.analyzers.entropy_analyzer import analyze_full_entropy
from app.core.analyzers.string_analyzer import extract_and_classify_strings
from app.core.analyzers.document_analyzer import analyze_document
from app.core.analyzers.apk_analyzer import analyze_apk
from app.core.analyzers.structural_analyzer import analyze_structure
from app.core.intel.malwarebazaar import MalwareBazaarClient

logger = logging.getLogger("cyberforge.static.stream")

async def run_analysis_stream(
    file_path: Path,
    yara_scanner=None,
    vt_client=None,
    abuseipdb_client=None,
    enable_vt: bool = True,
    enable_abuseipdb: bool = True,
    enable_dynamic: bool = False,
) -> AsyncGenerator[dict, None]:
    """
    Executes the static analysis pipeline and yields real-time progress events.
    """
    report = AnalysisReport(filename=file_path.name, analysis_start=time.time())
    mb_client = MalwareBazaarClient()
    
    # ── 1. Hashes ──────────────────────────────────────────────
    start = time.time()
    try:
        report.hashes = await asyncio.to_thread(compute_hashes, file_path)
        report.file_size = report.hashes.file_size
    except Exception as e:
        logger.error(f"Hash computation failed: {e}")
    yield {"stage": "hashing", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── 2. MIME type & Ext ───────────────────────────────────────────
    start = time.time()
    ext = file_path.suffix.lower().lstrip(".")
    report.file_type = ext.upper()
    report.mime_type = await asyncio.to_thread(_detect_mime, file_path)
    yield {"stage": "file_typing", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    pe_types = {"exe", "dll", "msi", "scr", "pif", "cpl", "sys", "drv"}
    doc_types = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "pdf"}
    
    # ── 3. PE parsing (only for executables) ───────────────────
    if ext in pe_types:
        start = time.time()
        try:
            report.pe_info = await asyncio.to_thread(parse_pe, file_path)
        except Exception:
            pass
        yield {"stage": "pe_parsing", "status": "complete", "duration_ms": int((time.time() - start)*1000)}
        
        start = time.time()
        struct_res = await asyncio.to_thread(analyze_structure, file_path)
        # We can store struct_res inside report.analysis_data later
        setattr(report, "structure", struct_res)
        yield {"stage": "structural_analysis", "status": "complete", "duration_ms": int((time.time() - start)*1000)}
        
    # ── 4. Deep Documents & APKs ───────────────────
    if ext in doc_types:
        start = time.time()
        doc_res = await asyncio.to_thread(analyze_document, file_path)
        setattr(report, "document", doc_res)
        yield {"stage": "document_analysis", "status": "complete", "duration_ms": int((time.time() - start)*1000)}
    elif ext == "apk":
        start = time.time()
        apk_res = await asyncio.to_thread(analyze_apk, file_path)
        setattr(report, "apk", apk_res)
        yield {"stage": "apk_analysis", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── 5. Entropy & Strings ───────────────────
    start = time.time()
    entropy_res = await asyncio.to_thread(analyze_full_entropy, file_path)
    setattr(report, "entropy", entropy_res)
    yield {"stage": "entropy_analysis", "status": "complete", "duration_ms": int((time.time() - start)*1000)}
    
    start = time.time()
    strings_res = await asyncio.to_thread(extract_and_classify_strings, file_path)
    setattr(report, "strings_analysis", strings_res)
    yield {"stage": "string_analysis", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── 6. YARA scanning ───────────────────────────────────────
    start = time.time()
    if yara_scanner:
        try:
            report.yara = await asyncio.to_thread(yara_scanner.scan_file, file_path)
        except Exception:
            pass
    matches = len(report.yara.matches) if report.yara else 0
    yield {"stage": "yara_scan", "status": "complete", "matches": matches, "duration_ms": int((time.time() - start)*1000)}

    # ── 7. IOC extraction ──────────────────────────────────────
    start = time.time()
    try:
        report.iocs = await asyncio.to_thread(extract_iocs, file_path)
    except Exception:
        pass
    yield {"stage": "ioc_extraction", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── 8. MITRE ATT&CK mapping ────────────────────────────────
    start = time.time()
    try:
        yara_families = list({m.family for m in report.yara.matches}) if report.yara else []
        suspicious_imports = []
        if report.pe_info:
            for imp in report.pe_info.imports:
                suspicious_imports.extend(imp.suspicious_funcs)
        pe_anomalies = report.pe_info.anomalies if report.pe_info else []
        report.mitre = await asyncio.to_thread(map_to_attack, yara_families, suspicious_imports, pe_anomalies)
    except Exception:
        pass
    yield {"stage": "mitre_mapping", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── 9. External Threat Intel ──────────────────────────────
    if enable_vt and vt_client and report.hashes:
        start = time.time()
        try:
            report.vt_result = await asyncio.to_thread(vt_client.lookup_hash, report.hashes.sha256)
        except Exception:
            pass
        yield {"stage": "virustotal_lookup", "status": "complete", "duration_ms": int((time.time() - start)*1000)}
        
    start = time.time()
    if report.hashes:
        mb_res = await asyncio.to_thread(mb_client.check_hash, report.hashes.sha256)
        setattr(report, "malwarebazaar", mb_res)
    yield {"stage": "malwarebazaar_lookup", "status": "complete", "duration_ms": int((time.time() - start)*1000)}

    # ── Finalize ───────────────────────────────────────────────
    start = time.time()
    report.risk_score = min(_EXT_BASE_RISK.get(ext, 8) + (20 if getattr(report, "entropy", {}).get("is_packed") else 0), 100)
    report.threat_level = _score_to_level(report.risk_score)
    report.finalize()
    
    # Store dynamic fields dynamically onto the report object before yield so the DB commit has them
    yield {"stage": "finalizing_report", "status": "complete", "report_obj": report, "duration_ms": int((time.time() - start)*1000)}
