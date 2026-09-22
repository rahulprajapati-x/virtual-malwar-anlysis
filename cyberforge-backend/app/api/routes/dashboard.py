"""
CyberForge — Dashboard & IOC Database Routes
Aggregate statistics and global IOC lookups across all samples.
"""
import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.models import Sample, Case, IOC
from app.schemas.schemas import DashboardStats, IOCResponse

router = APIRouter(prefix="/api", tags=["Dashboard & IOC DB"])


@router.get("/dashboard/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    today = datetime.datetime.utcnow().date()
    today_start = datetime.datetime.combine(today, datetime.time.min)

    total_files = db.query(func.count(Sample.id)).scalar() or 0
    active_cases = db.query(func.count(Case.id)).filter(Case.status == "Active").scalar() or 0
    threats = db.query(func.count(Sample.id)).filter(
        Sample.threat_level.in_(["CRITICAL", "HIGH", "MEDIUM"])
    ).scalar() or 0
    total_iocs = db.query(func.count(IOC.id)).scalar() or 0

    files_today = db.query(func.count(Sample.id)).filter(
        Sample.submitted_at >= today_start
    ).scalar() or 0

    threats_today = db.query(func.count(Sample.id)).filter(
        Sample.submitted_at >= today_start,
        Sample.threat_level.in_(["CRITICAL", "HIGH", "MEDIUM"])
    ).scalar() or 0

    return DashboardStats(
        total_files_analyzed=total_files,
        active_cases=active_cases,
        total_threats_found=threats,
        total_iocs_extracted=total_iocs,
        files_today=files_today,
        threats_today=threats_today,
    )


@router.get("/dashboard/weekly-activity")
def weekly_activity(db: Session = Depends(get_db)):
    """7-day rolling activity: files analyzed and threats found per day."""
    results = []
    today = datetime.datetime.utcnow().date()

    for i in range(6, -1, -1):
        day = today - datetime.timedelta(days=i)
        day_start = datetime.datetime.combine(day, datetime.time.min)
        day_end = datetime.datetime.combine(day, datetime.time.max)

        files = db.query(func.count(Sample.id)).filter(
            Sample.submitted_at.between(day_start, day_end)
        ).scalar() or 0

        threats = db.query(func.count(Sample.id)).filter(
            Sample.submitted_at.between(day_start, day_end),
            Sample.threat_level.in_(["CRITICAL", "HIGH"])
        ).scalar() or 0

        results.append({
            "day": day.strftime("%a"),
            "date": day.isoformat(),
            "files": files,
            "threats": threats,
        })

    return results


@router.get("/dashboard/threat-families")
def threat_families(db: Session = Depends(get_db)):
    """Breakdown of detected threats by malware family (from IOC table)."""
    results = db.query(
        IOC.family, func.count(IOC.id).label("count")
    ).filter(IOC.family != "Unknown").group_by(IOC.family).order_by(func.count(IOC.id).desc()).limit(8).all()

    return [{"name": r[0], "count": r[1]} for r in results]


# ── Global IOC database ──────────────────────────────────────────
@router.get("/iocs", response_model=list[IOCResponse])
def search_iocs(
    ioc_type: str = None,
    value_search: str = None,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
):
    """Search across all extracted IOCs from all samples."""
    query = db.query(IOC)
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    if value_search:
        query = query.filter(IOC.value.ilike(f"%{value_search}%"))
    return query.order_by(IOC.first_seen.desc()).limit(limit).all()


@router.get("/iocs/export")
def export_iocs(format: str = "json", db: Session = Depends(get_db)):
    """Export all IOCs (for sharing with threat intel platforms like MISP)."""
    iocs = db.query(IOC).all()

    if format == "stix":
        # Minimal STIX 2.1 bundle structure
        objects = []
        for ioc in iocs:
            stix_type = {
                "domain": "domain-name", "ip": "ipv4-addr",
                "url": "url", "wallet": "x-crypto-wallet",
            }.get(ioc.ioc_type, "artifact")
            objects.append({
                "type": "indicator",
                "id": f"indicator--{ioc.id}",
                "pattern": f"[{stix_type}:value = '{ioc.value}']",
                "pattern_type": "stix",
                "created": ioc.first_seen.isoformat(),
                "labels": [ioc.family] if ioc.family != "Unknown" else [],
            })
        return {"type": "bundle", "objects": objects}

    return [
        {
            "type": ioc.ioc_type, "value": ioc.value, "family": ioc.family,
            "confidence": ioc.confidence, "first_seen": ioc.first_seen.isoformat(),
        }
        for ioc in iocs
    ]
