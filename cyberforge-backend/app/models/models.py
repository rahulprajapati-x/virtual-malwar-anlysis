"""
CyberForge — Database Models
SQLAlchemy ORM models for case management, sample storage, and analysis results.
"""
import uuid
import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship, declarative_base
# UUID dialect import not needed — using String PKs with gen_uuid() helper instead

Base = declarative_base()


def gen_uuid():
    return str(uuid.uuid4())


class Case(Base):
    """An investigation case — groups related samples and evidence."""
    __tablename__ = "cases"

    id          = Column(String, primary_key=True, default=gen_uuid)
    case_number = Column(String, unique=True, nullable=False, index=True)  # e.g. CS-2026-001
    name        = Column(String, nullable=False)
    description = Column(Text, default="")
    status      = Column(String, default="Active")     # Active / Review / Closed
    severity    = Column(String, default="MEDIUM")      # CRITICAL/HIGH/MEDIUM/LOW
    analyst     = Column(String, default="")
    agency      = Column(String, default="")            # which department/unit
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    closed_at   = Column(DateTime, nullable=True)

    samples = relationship("Sample", back_populates="case", cascade="all, delete-orphan")
    notes   = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")


class CaseNote(Base):
    """Investigator notes / chain-of-custody log entries on a case."""
    __tablename__ = "case_notes"

    id         = Column(String, primary_key=True, default=gen_uuid)
    case_id    = Column(String, ForeignKey("cases.id"), nullable=False)
    author     = Column(String, default="")
    content    = Column(Text, nullable=False)
    note_type  = Column(String, default="comment")  # comment / custody / action
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    case = relationship("Case", back_populates="notes")


class Sample(Base):
    """A submitted file sample for analysis."""
    __tablename__ = "samples"

    id            = Column(String, primary_key=True, default=gen_uuid)
    case_id       = Column(String, ForeignKey("cases.id"), nullable=True)

    filename      = Column(String, nullable=False)
    file_size     = Column(Integer, default=0)
    file_type     = Column(String, default="")
    mime_type     = Column(String, default="")
    storage_path  = Column(String, nullable=False)   # path on disk

    sha256        = Column(String, index=True)
    sha1          = Column(String, index=True)
    md5           = Column(String, index=True)
    sha512        = Column(String, nullable=True)
    imphash       = Column(String, nullable=True)
    ssdeep_hash   = Column(String, nullable=True)

    risk_score    = Column(Integer, default=0)
    threat_level  = Column(String, default="CLEAN")

    status        = Column(String, default="pending")  # pending / analyzing / complete / failed
    sandbox_status = Column(String, nullable=True)       # queued / running / complete / failed / skipped
    submitted_by  = Column(String, default="")
    submitted_at  = Column(DateTime, default=datetime.datetime.utcnow)
    analyzed_at   = Column(DateTime, nullable=True)

    # Full analysis JSON blob (PE info, YARA matches, IOCs, MITRE, behaviors, VT result)
    analysis_data = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="samples")
    iocs = relationship("IOC", back_populates="sample", cascade="all, delete-orphan")


class IOC(Base):
    """An Indicator of Compromise extracted from a sample (normalized, queryable)."""
    __tablename__ = "iocs"

    id          = Column(String, primary_key=True, default=gen_uuid)
    sample_id   = Column(String, ForeignKey("samples.id"), nullable=False)

    ioc_type    = Column(String, nullable=False)   # domain / ip / url / hash / regkey / wallet / mutex
    value       = Column(String, nullable=False, index=True)
    family      = Column(String, default="")
    confidence  = Column(String, default="MEDIUM")

    # Threat intel enrichment (if VT/AbuseIPDB queried)
    vt_verdict       = Column(String, nullable=True)
    abuseipdb_score  = Column(Integer, nullable=True)

    first_seen  = Column(DateTime, default=datetime.datetime.utcnow)

    sample = relationship("Sample", back_populates="iocs")


class AuditLog(Base):
    """
    Evidence integrity / audit trail.
    Every action on a sample or case is logged for court-admissible chain of custody.
    """
    __tablename__ = "audit_logs"

    id          = Column(String, primary_key=True, default=gen_uuid)
    entity_type = Column(String, nullable=False)   # 'sample' / 'case'
    entity_id   = Column(String, nullable=False)
    action      = Column(String, nullable=False)   # 'uploaded' / 'analyzed' / 'viewed' / 'exported' / 'note_added'
    actor       = Column(String, default="system")
    details     = Column(Text, default="")
    ip_address  = Column(String, nullable=True)
    timestamp   = Column(DateTime, default=datetime.datetime.utcnow)


class User(Base):
    """Analyst / investigator user account (RBAC-ready)."""
    __tablename__ = "users"

    id            = Column(String, primary_key=True, default=gen_uuid)
    username      = Column(String, unique=True, nullable=False, index=True)
    email         = Column(String, unique=True, nullable=False)
    full_name     = Column(String, default="")
    hashed_password = Column(String, nullable=False)
    role          = Column(String, default="analyst")  # admin / analyst / viewer
    agency        = Column(String, default="")
    badge_number  = Column(String, nullable=True)
    is_active     = Column(Boolean, default=True)
    mfa_enabled   = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    last_login    = Column(DateTime, nullable=True)
