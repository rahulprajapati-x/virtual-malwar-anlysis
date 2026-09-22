"""
CyberForge — Report Generation Route
Generates and streams downloadable PDF forensic reports.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.database import get_db
from app.models.models import Sample, Case, AuditLog
from app.core.report_generator import generate_forensic_report

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/sample/{sample_id}/pdf")
def download_report(sample_id: str, db: Session = Depends(get_db)):
    """Generate and download a court-admissible PDF forensic report for a sample."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")
    if not sample.analysis_data:
        raise HTTPException(400, "Sample has not been analyzed yet")

    case = None
    if sample.case_id:
        case = db.query(Case).filter(Case.id == sample.case_id).first()

    pdf_bytes = generate_forensic_report(sample, case)

    db.add(AuditLog(
        entity_type="sample", entity_id=sample_id, action="report_exported",
        details=f"PDF report generated for {sample.filename}"
    ))
    db.commit()

    filename = f"CyberForge_Report_{sample.filename}_{sample_id[:8]}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
