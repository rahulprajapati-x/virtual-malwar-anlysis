"""
CyberForge — Sample Upload & Analysis Routes
Handles file submission, triggers static analysis pipeline, returns results.
"""
import uuid
import logging
import datetime
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.models import Sample, IOC, AuditLog, Case
from app.schemas.schemas import UploadResponse, SampleResponse, SampleDetailResponse
from app.core.static_analyzer import run_analysis
from app.core.yara_scanner import YARAScanner
from app.core.intel.virustotal import VirusTotalClient
from app.core.intel.abuseipdb import AbuseIPDBClient
from app.core.static_stream import run_analysis_stream
import asyncio
from datetime import datetime, timezone

logger = logging.getLogger("cyberforge.api.samples")
router = APIRouter(prefix="/api/samples", tags=["Samples"])

# Initialize engines once (module-level singletons)
_yara_scanner = None
_vt_client = None
_abuseipdb_client = None


def get_yara_scanner() -> YARAScanner:
    global _yara_scanner
    if _yara_scanner is None:
        _yara_scanner = YARAScanner(settings.yara_rules_path)
    return _yara_scanner


def get_vt_client() -> VirusTotalClient:
    global _vt_client
    if _vt_client is None:
        _vt_client = VirusTotalClient(settings.VIRUSTOTAL_API_KEY)
    return _vt_client


def get_abuseipdb_client() -> AbuseIPDBClient:
    global _abuseipdb_client
    if _abuseipdb_client is None:
        _abuseipdb_client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)
    return _abuseipdb_client


def _log_audit(db: Session, entity_type: str, entity_id: str, action: str,
                actor: str = "system", details: str = ""):
    entry = AuditLog(
        entity_type=entity_type, entity_id=entity_id,
        action=action, actor=actor, details=details,
    )
    db.add(entry)
    db.commit()


async def _save_uploaded_file(
    file: UploadFile,
    storage_path: Path,
    max_bytes: int,
    max_mb: int,
    sample_id: str,
) -> int:
    """
    Streams an uploaded file to disk in 1 MB chunks.
    Returns the total number of bytes written.
    Raises HTTPException on size-exceeded or write errors.
    """
    CHUNK = 1 * 1024 * 1024  # 1 MB
    total_written = 0
    try:
        with open(storage_path, "wb") as out:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > max_bytes:
                    out.close()
                    storage_path.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"File exceeds maximum allowed size of {max_mb} MB",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        storage_path.unlink(missing_ok=True)
        logger.error(f"File write error for {sample_id}: {exc}")
        raise HTTPException(500, f"Failed to save uploaded file: {exc}")

    if total_written == 0:
        storage_path.unlink(missing_ok=True)
        raise HTTPException(400, "Empty file submitted")

    return total_written


@router.post("/upload", response_model=UploadResponse)
async def upload_sample(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    case_id: str = Form(None),
    submitted_by: str = Form("analyst"),
    enable_dynamic: bool = Form(False),
    enable_stream: bool = Form(False),
    db: Session = Depends(get_db),
):
    """
    Upload a file sample for analysis.
    Saves the file using chunked streaming (no full RAM load) — supports up to 500 MB.
    Triggers analysis in the background after save.
    """
    sample_id   = str(uuid.uuid4())
    safe_filename = Path(file.filename).name
    storage_path  = settings.upload_path / f"{sample_id}_{safe_filename}"

    total_written = await _save_uploaded_file(
        file, storage_path, settings.max_file_bytes, settings.MAX_FILE_SIZE_MB, sample_id
    )

    # Create DB record
    ext = Path(safe_filename).suffix.lstrip(".").upper()
    sample = Sample(
        id=sample_id,
        case_id=case_id,
        filename=safe_filename,
        file_size=total_written,
        file_type=ext,
        storage_path=str(storage_path),
        status="pending",
        submitted_by=submitted_by,
    )
    db.add(sample)
    db.commit()

    _log_audit(db, "sample", sample_id, "uploaded", submitted_by,
               f"File: {safe_filename} ({total_written} bytes)")

    # Trigger background analysis only if not streaming
    if not enable_stream:
        background_tasks.add_task(_run_background_analysis, sample_id, storage_path, enable_dynamic)

    return UploadResponse(
        sample_id=sample_id,
        filename=safe_filename,
        status="pending",
        message="File uploaded. Analysis running in background — poll GET /api/samples/{id} for results.",
    )


@router.post("/upload-sync", response_model=SampleDetailResponse)
async def upload_and_analyze_sync(
    file: UploadFile = File(...),
    case_id: str = Form(None),
    submitted_by: str = Form("analyst"),
    enable_dynamic: bool = Form(False),
    db: Session = Depends(get_db),
):
    """
    Upload AND analyze synchronously in one request.
    Uses chunked streaming save — supports large files up to 500 MB.
    """
    sample_id    = str(uuid.uuid4())
    safe_filename = Path(file.filename).name
    storage_path  = settings.upload_path / f"{sample_id}_{safe_filename}"

    total_written = await _save_uploaded_file(
        file, storage_path, settings.max_file_bytes, settings.MAX_FILE_SIZE_MB, sample_id
    )

    ext = Path(safe_filename).suffix.lstrip(".").upper()
    sample = Sample(
        id=sample_id,
        case_id=case_id,
        filename=safe_filename,
        file_size=total_written,
        file_type=ext,
        storage_path=str(storage_path),
        status="analyzing",
        sandbox_status="queued" if enable_dynamic else "skipped",
        submitted_by=submitted_by,
    )
    db.add(sample)
    db.commit()

    _log_audit(db, "sample", sample_id, "uploaded", submitted_by, f"File: {safe_filename}")

    # Run analysis synchronously
    try:
        if enable_dynamic:
            sample.sandbox_status = "running"
            db.commit()
        report = run_analysis(
            storage_path,
            yara_scanner=get_yara_scanner(),
            vt_client=get_vt_client(),
            abuseipdb_client=get_abuseipdb_client(),
            enable_vt=bool(settings.VIRUSTOTAL_API_KEY),
            enable_abuseipdb=bool(settings.ABUSEIPDB_API_KEY),
            enable_dynamic=enable_dynamic,
        )
        _persist_analysis(db, sample, report)
        _log_audit(db, "sample", sample_id, "analyzed", "system",
                   f"Risk: {report.risk_score}/100 ({report.threat_level})")
    except Exception as e:
        logger.error(f"Analysis failed for {sample_id}: {e}")
        sample.status = "failed"
        db.commit()
        raise HTTPException(500, f"Analysis failed: {str(e)}")

    db.refresh(sample)
    return sample


def _persist_analysis(db: Session, sample: Sample, report):
    """Save analysis results to DB, including normalized IOC records."""
    sample.sha256 = report.hashes.sha256 if report.hashes else None
    sample.sha1 = report.hashes.sha1 if report.hashes else None
    sample.md5 = report.hashes.md5 if report.hashes else None
    sample.sha512 = report.hashes.sha512 if report.hashes else None
    sample.imphash = report.hashes.imphash if report.hashes else None
    sample.ssdeep_hash = report.hashes.ssdeep if report.hashes else None
    sample.mime_type = report.mime_type
    sample.risk_score = report.risk_score
    sample.threat_level = report.threat_level
    sample.status = "complete"
    sample.analyzed_at = datetime.now(timezone.utc)
    sample.analysis_data = report.to_dict()

    # Update sandbox_status from dynamic result
    if report.dynamic_result:
        sample.sandbox_status = (
            "complete" if not report.dynamic_result.error else "failed"
        )

    # Normalize IOCs into queryable rows
    if report.iocs:
        ioc_map = {
            "domain": report.iocs.domains,
            "ip": report.iocs.ips,
            "url": report.iocs.urls,
            "regkey": report.iocs.registry_keys,
            "filepath": report.iocs.file_paths,
            "mutex": report.iocs.mutexes,
            "wallet": report.iocs.crypto_wallets,
        }
        for ioc_type, values in ioc_map.items():
            for val in values:
                ioc_record = IOC(
                    sample_id=sample.id,
                    ioc_type=ioc_type,
                    value=val,
                    family=report.yara.matches[0].family if report.yara and report.yara.matches else "Unknown",
                    confidence="HIGH" if report.threat_level in ("CRITICAL", "HIGH") else "MEDIUM",
                )
                db.add(ioc_record)

    # Persist dynamic sandbox network IOCs as separate HIGH-confidence IOC rows
    if report.dynamic_result and report.dynamic_result.network_iocs:
        existing_vals = {r.value for r in db.query(IOC).filter(IOC.sample_id == sample.id).all()}
        for net_ioc in report.dynamic_result.network_iocs:
            val = net_ioc.get("value", "")
            if val and val not in existing_vals:
                db.add(IOC(
                    sample_id=sample.id,
                    ioc_type=net_ioc.get("type", "ip"),
                    value=val,
                    family=report.yara.matches[0].family if report.yara and report.yara.matches else "Dynamic",
                    confidence="HIGH",
                ))
                existing_vals.add(val)

    db.commit()


def _run_background_analysis(sample_id: str, storage_path: Path, enable_dynamic: bool = False):
    """Background task — runs analysis and updates DB (own session)."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        sample = db.query(Sample).filter(Sample.id == sample_id).first()
        if not sample:
            return
        sample.status = "analyzing"
        if enable_dynamic:
            sample.sandbox_status = "running"
        db.commit()

        report = run_analysis(
            storage_path,
            yara_scanner=get_yara_scanner(),
            vt_client=get_vt_client(),
            abuseipdb_client=get_abuseipdb_client(),
            enable_vt=bool(settings.VIRUSTOTAL_API_KEY),
            enable_abuseipdb=bool(settings.ABUSEIPDB_API_KEY),
            enable_dynamic=enable_dynamic,
        )
        _persist_analysis(db, sample, report)
        _log_audit(db, "sample", sample_id, "analyzed", "system",
                   f"Risk: {report.risk_score}/100")
    except Exception as e:
        logger.error(f"Background analysis failed for {sample_id}: {e}")
        sample = db.query(Sample).filter(Sample.id == sample_id).first()
        if sample:
            sample.status = "failed"
            db.commit()
    finally:
        db.close()


@router.get("/{sample_id}", response_model=SampleDetailResponse)
def get_sample(sample_id: str, db: Session = Depends(get_db)):
    """Get full analysis results for a sample."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")
    return sample


@router.get("", response_model=list[SampleResponse])
def list_samples(
    case_id: str = None,
    threat_level: str = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """List samples, optionally filtered by case or threat level."""
    query = db.query(Sample)
    if case_id:
        query = query.filter(Sample.case_id == case_id)
    if threat_level:
        query = query.filter(Sample.threat_level == threat_level)
    return query.order_by(Sample.submitted_at.desc()).limit(limit).all()


@router.delete("/{sample_id}")
def delete_sample(sample_id: str, db: Session = Depends(get_db)):
    """Delete a sample and its file from disk."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    # Remove file from disk
    try:
        Path(sample.storage_path).unlink(missing_ok=True)
    except Exception as e:
        logger.warning(f"Could not delete file: {e}")

    db.delete(sample)
    db.commit()
    return {"message": "Sample deleted"}


@router.post("/{sample_id}/rescan")
def rescan_sample(sample_id: str, db: Session = Depends(get_db)):
    """Re-run analysis on an already-uploaded sample (e.g. after YARA rule updates)."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    storage_path = Path(sample.storage_path)
    if not storage_path.exists():
        raise HTTPException(410, "Original file no longer on disk")

    report = run_analysis(
        storage_path,
        yara_scanner=get_yara_scanner(),
        vt_client=get_vt_client(),
        abuseipdb_client=get_abuseipdb_client(),
    )
    # Clear old IOCs before re-persisting
    db.query(IOC).filter(IOC.sample_id == sample_id).delete()
    _persist_analysis(db, sample, report)
    _log_audit(db, "sample", sample_id, "rescanned", "system", f"New risk: {report.risk_score}")

    db.refresh(sample)
    return sample


@router.post("/{sample_id}/sandbox")
def run_sandbox(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """
    Run (or re-run) dynamic sandbox analysis on an already-uploaded sample.
    Returns the sandbox result and updated sample with merged risk score.
    """
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    storage_path = Path(sample.storage_path)
    if not storage_path.exists():
        raise HTTPException(410, "Original file no longer on disk")

    if sample.status != "complete":
        raise HTTPException(400, "Sample must be fully analyzed before sandbox execution")

    # Re-run full analysis with dynamic sandbox enabled
    sample.sandbox_status = "running"
    db.commit()

    try:
        report = run_analysis(
            storage_path,
            yara_scanner=get_yara_scanner(),
            vt_client=get_vt_client(),
            abuseipdb_client=get_abuseipdb_client(),
            enable_vt=bool(settings.VIRUSTOTAL_API_KEY),
            enable_abuseipdb=bool(settings.ABUSEIPDB_API_KEY),
            enable_dynamic=True,
        )
        # Clear old IOCs and re-persist with dynamic additions
        db.query(IOC).filter(IOC.sample_id == sample_id).delete()
        _persist_analysis(db, sample, report)
        _log_audit(db, "sample", sample_id, "sandbox_run", "system",
                   f"Dynamic: {len(report.dynamic_result.events if report.dynamic_result else [])} events, "
                   f"verdict={report.dynamic_result.sandbox_verdict if report.dynamic_result else 'N/A'}")
    except Exception as e:
        sample.sandbox_status = "failed"
        db.commit()
        raise HTTPException(500, f"Sandbox execution failed: {str(e)}")

    db.refresh(sample)
    return sample


@router.patch("/{sample_id}/case", response_model=SampleResponse)
def assign_case(sample_id: str, case_id: str = Form(...), db: Session = Depends(get_db)):
    """Assign (or move) a sample to a case — used to file analyzed samples into investigations."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    sample.case_id = case_id
    db.commit()
    db.refresh(sample)

    _log_audit(db, "sample", sample_id, "filed_to_case", "analyst",
               f"Assigned to case {case.case_number}: {case.name}")
    return sample


@router.post("/{sample_id}/intel/enrich")
def enrich_sample_intel(sample_id: str, db: Session = Depends(get_db)):
    """
    On-demand re-enrichment of a sample's IP geolocation, domain intel,
    AbuseIPDB reputation, and VirusTotal domain verdicts.

    This is a lightweight operation — it does NOT re-run file analysis or YARA.
    It re-fetches all network-intelligence data and updates the stored analysis_data.

    Useful for:
    - Enriching previously-analyzed samples (before these features existed)
    - Refreshing stale geo/abuse data
    - Querying VT domain verdicts for a sample analyzed before VT key was configured
    """
    import json
    from app.core.intel.ip_geo import geolocate_ips, classify_domain_risk
    from app.core.intel.abuseipdb import AbuseIPDBClient
    from app.core.intel.virustotal import VirusTotalClient

    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")

    if sample.status != "complete":
        raise HTTPException(400, "Sample analysis must be complete before enrichment")

    # Load existing analysis data
    try:
        analysis = sample.analysis_data or {}
        if isinstance(analysis, str):
            analysis = json.loads(analysis)
    except Exception:
        analysis = {}

    iocs = analysis.get("iocs", {})
    public_ips = iocs.get("ips", [])[:30]
    domains_list = iocs.get("domains", [])
    ddns_list = iocs.get("ddns_domains", [])
    enrichment_log = []

    # ── 1. IP Geolocation (free, always runs) ──
    if public_ips:
        try:
            geo_results = geolocate_ips(public_ips)
            analysis["ip_geo_results"] = {ip: geo.to_dict() for ip, geo in geo_results.items()}
            enrichment_log.append(f"Geolocated {len(geo_results)} IPs")
        except Exception as e:
            enrichment_log.append(f"Geo failed: {e}")

    # ── 2. Domain C2 Intelligence (heuristic, always runs) ──
    if domains_list or ddns_list:
        try:
            ddns_set = set(ddns_list)
            all_domains = list(set(domains_list + list(ddns_set)))
            domain_intel = []
            for domain in all_domains[:50]:
                is_ddns = domain in ddns_set
                intel = classify_domain_risk(domain, is_ddns=is_ddns)
                domain_intel.append(intel)
            risk_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
            domain_intel.sort(key=lambda x: -risk_rank.get(x.get("risk_level", "CLEAN"), 0))
            analysis["domain_intel"] = domain_intel
            enrichment_log.append(f"Scored {len(domain_intel)} domains")
        except Exception as e:
            enrichment_log.append(f"Domain scoring failed: {e}")

    # ── 3. AbuseIPDB (only if API key configured) ──
    if public_ips and settings.ABUSEIPDB_API_KEY:
        try:
            client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)
            abuse_results = []
            for ip in public_ips[:15]:
                result = client.check_ip(ip)
                abuse_results.append(result.to_dict())
            analysis["abuseipdb"] = abuse_results
            enrichment_log.append(f"AbuseIPDB checked {len(abuse_results)} IPs")
        except Exception as e:
            enrichment_log.append(f"AbuseIPDB failed: {e}")

    # ── 4. VirusTotal Domain Batch (only if API key configured) ──
    domain_intel_current = analysis.get("domain_intel", [])
    top_high_domains = [
        d["domain"] for d in domain_intel_current
        if d.get("risk_level") in ("HIGH", "MEDIUM")
    ][:3]

    if top_high_domains and settings.VIRUSTOTAL_API_KEY:
        try:
            vt = VirusTotalClient(settings.VIRUSTOTAL_API_KEY)
            vt_domain_results = vt.lookup_domain_batch(top_high_domains, max_domains=3)
            analysis["vt_domain_results"] = vt_domain_results
            enrichment_log.append(
                f"VT domain lookup: {len(vt_domain_results)} domain(s) checked"
            )
        except Exception as e:
            enrichment_log.append(f"VT domain lookup failed: {e}")

    # ── Persist updated analysis ──
    import json as _json
    sample.analysis_data = _json.dumps(analysis)
    db.commit()
    db.refresh(sample)

    _log_audit(db, "sample", sample_id, "intel_enriched", "analyst",
               f"Enrichment: {'; '.join(enrichment_log)}")

    logger.info(f"Intel enrichment for {sample_id}: {'; '.join(enrichment_log)}")

    return {
        "sample_id": sample_id,
        "enrichment_log": enrichment_log,
        "ip_count": len(public_ips),
        "domain_count": len(domains_list) + len(ddns_list),
        "vt_domains_checked": len(top_high_domains) if settings.VIRUSTOTAL_API_KEY else 0,
        "abuseipdb_checked": len(public_ips[:15]) if settings.ABUSEIPDB_API_KEY else 0,
    }


@router.websocket("/stream/{sample_id}")
async def stream_analysis(websocket: WebSocket, sample_id: str, db: Session = Depends(get_db)):
    await websocket.accept()
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        await websocket.close(code=1008)
        return

    file_path = Path(sample.storage_path)
    if not file_path.exists():
        await websocket.close(code=1008)
        return

    try:
        # Run the streaming generator
        async for event in run_analysis_stream(
            file_path,
            yara_scanner=get_yara_scanner(),
            vt_client=get_vt_client(),
            abuseipdb_client=get_abuseipdb_client(),
            enable_vt=bool(settings.VIRUSTOTAL_API_KEY),
            enable_abuseipdb=bool(settings.ABUSEIPDB_API_KEY)
        ):
            if event["stage"] == "finalizing_report":
                report = event.pop("report_obj")
                _persist_analysis(db, sample, report)
                db.refresh(sample)
                event["sample"] = {
                    "id": sample.id,
                    "filename": sample.filename,
                    "risk_score": sample.risk_score,
                    "threat_level": sample.threat_level,
                    "analysis_data": sample.analysis_data
                }
            await websocket.send_json(event)
            await asyncio.sleep(0.01) # Yield to event loop
            
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        logger.info(f"Client disconnected from static stream for {sample_id}")
    except Exception as e:
        logger.error(f"Error in static stream: {e}")
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
