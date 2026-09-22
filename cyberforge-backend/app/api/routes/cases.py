"""
CyberForge — Case Management Routes
CRUD operations for investigation cases, with chain-of-custody notes.
"""
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.models import Case, CaseNote, Sample, AuditLog
from app.schemas.schemas import (
    CaseCreate, CaseUpdate, CaseResponse,
    CaseNoteCreate, CaseNoteResponse,
)

router = APIRouter(prefix="/api/cases", tags=["Cases"])


def _next_case_number(db: Session) -> str:
    year = datetime.datetime.utcnow().year
    count = db.query(func.count(Case.id)).filter(
        Case.case_number.like(f"CS-{year}-%")
    ).scalar()
    return f"CS-{year}-{(count or 0) + 1:03d}"


@router.post("", response_model=CaseResponse)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    case = Case(
        case_number=_next_case_number(db),
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        analyst=payload.analyst,
        agency=payload.agency,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    db.add(AuditLog(entity_type="case", entity_id=case.id, action="created",
                     actor=payload.analyst, details=f"Case opened: {payload.name}"))
    db.commit()

    return CaseResponse(
        **{c.name: getattr(case, c.name) for c in case.__table__.columns},
        sample_count=0,
    )


@router.get("", response_model=list[CaseResponse])
def list_cases(status: str = None, db: Session = Depends(get_db)):
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status)
    cases = query.order_by(Case.created_at.desc()).all()

    results = []
    for case in cases:
        sample_count = db.query(func.count(Sample.id)).filter(Sample.case_id == case.id).scalar()
        results.append(CaseResponse(
            **{c.name: getattr(case, c.name) for c in case.__table__.columns},
            sample_count=sample_count or 0,
        ))
    return results


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    sample_count = db.query(func.count(Sample.id)).filter(Sample.case_id == case.id).scalar()
    return CaseResponse(
        **{c.name: getattr(case, c.name) for c in case.__table__.columns},
        sample_count=sample_count or 0,
    )


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(case, field, value)

    if update_data.get("status") == "Closed" and not case.closed_at:
        case.closed_at = datetime.datetime.utcnow()

    case.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(case)

    db.add(AuditLog(entity_type="case", entity_id=case.id, action="updated",
                     details=str(update_data)))
    db.commit()

    sample_count = db.query(func.count(Sample.id)).filter(Sample.case_id == case.id).scalar()
    return CaseResponse(
        **{c.name: getattr(case, c.name) for c in case.__table__.columns},
        sample_count=sample_count or 0,
    )


@router.delete("/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    db.delete(case)
    db.commit()
    return {"message": "Case deleted"}


# ── Case notes / chain of custody ───────────────────────────────
@router.post("/{case_id}/notes", response_model=CaseNoteResponse)
def add_note(case_id: str, payload: CaseNoteCreate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    note = CaseNote(
        case_id=case_id,
        author=payload.author,
        content=payload.content,
        note_type=payload.note_type,
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    db.add(AuditLog(entity_type="case", entity_id=case_id, action="note_added",
                     actor=payload.author, details=payload.content[:200]))
    db.commit()

    return note


@router.get("/{case_id}/notes", response_model=list[CaseNoteResponse])
def list_notes(case_id: str, db: Session = Depends(get_db)):
    return db.query(CaseNote).filter(CaseNote.case_id == case_id)\
        .order_by(CaseNote.created_at.desc()).all()
