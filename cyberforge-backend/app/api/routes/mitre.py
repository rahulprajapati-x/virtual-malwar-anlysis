"""
CyberForge — MITRE ATT&CK Matrix Route
Aggregates detected techniques across all samples for the org-wide ATT&CK heatmap.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
import json

from app.database import get_db
from app.models.models import Sample

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

# Static tactic reference (full Enterprise ATT&CK tactic list, ordered by kill chain)
TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]


@router.get("/matrix")
def get_matrix(db: Session = Depends(get_db)):
    """
    Returns the ATT&CK matrix with detection counts.
    Aggregates technique hits across all analyzed samples (organization-wide visibility).
    """
    samples = db.query(Sample.analysis_data).filter(Sample.analysis_data.isnot(None)).all()

    technique_hits = {}  # technique_id -> {name, tactic, count}

    for (analysis_data,) in samples:
        if not analysis_data:
            continue
        mitre_list = analysis_data.get("mitre", [])
        for t in mitre_list:
            tid = t.get("id")
            if not tid:
                continue
            if tid not in technique_hits:
                technique_hits[tid] = {
                    "id": tid,
                    "name": t.get("name", ""),
                    "tactic": t.get("tactic", ""),
                    "count": 0,
                }
            technique_hits[tid]["count"] += 1

    # Group into tactic columns
    matrix = []
    for tactic in TACTICS:
        techniques = [
            t for t in technique_hits.values()
            if t["tactic"].lower() == tactic["name"].lower()
        ]
        matrix.append({
            "tactic_id": tactic["id"],
            "tactic_name": tactic["name"],
            "techniques": sorted(techniques, key=lambda x: -x["count"]),
        })

    return {
        "matrix": matrix,
        "total_techniques_detected": len(technique_hits),
        "total_samples_analyzed": len(samples),
    }


@router.get("/technique/{technique_id}/samples")
def samples_with_technique(technique_id: str, db: Session = Depends(get_db)):
    """Find all samples that triggered a specific MITRE technique."""
    samples = db.query(Sample).filter(Sample.analysis_data.isnot(None)).all()

    matches = []
    for sample in samples:
        mitre_list = (sample.analysis_data or {}).get("mitre", [])
        if any(t.get("id") == technique_id for t in mitre_list):
            matches.append({
                "sample_id": sample.id,
                "filename": sample.filename,
                "sha256": sample.sha256,
                "threat_level": sample.threat_level,
                "risk_score": sample.risk_score,
            })

    return {"technique_id": technique_id, "matched_samples": matches}
