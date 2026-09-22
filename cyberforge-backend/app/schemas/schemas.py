"""
CyberForge — Pydantic Schemas
Request/response models for the API layer.
"""
from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


# ── Case schemas ─────────────────────────────────────────────────
class CaseCreate(BaseModel):
    name: str
    description: str = ""
    severity: str = "MEDIUM"
    analyst: str = ""
    agency: str = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    analyst: Optional[str] = None


class CaseResponse(BaseModel):
    id: str
    case_number: str
    name: str
    description: str
    status: str
    severity: str
    analyst: str
    agency: str
    created_at: datetime
    updated_at: datetime
    sample_count: int = 0

    class Config:
        from_attributes = True


class CaseNoteCreate(BaseModel):
    author: str
    content: str
    note_type: str = "comment"


class CaseNoteResponse(BaseModel):
    id: str
    case_id: str
    author: str
    content: str
    note_type: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Sample / Analysis schemas ───────────────────────────────────
class SampleResponse(BaseModel):
    id: str
    case_id: Optional[str]
    filename: str
    file_size: int
    file_type: str
    mime_type: str
    sha256: str
    sha1: str
    md5: str
    risk_score: int
    threat_level: str
    status: str
    sandbox_status: Optional[str] = None
    submitted_at: datetime
    analyzed_at: Optional[datetime]

    class Config:
        from_attributes = True


class SampleDetailResponse(SampleResponse):
    analysis_data: Optional[dict] = None

    class Config:
        from_attributes = True


class UploadResponse(BaseModel):
    sample_id: str
    filename: str
    status: str
    message: str


# ── IOC schemas ──────────────────────────────────────────────────
class IOCResponse(BaseModel):
    id: str
    sample_id: str
    ioc_type: str
    value: str
    family: str
    confidence: str
    vt_verdict: Optional[str]
    abuseipdb_score: Optional[int]
    first_seen: datetime

    class Config:
        from_attributes = True


# ── CIPHER AI chat schemas ──────────────────────────────────────
class ChatMessage(BaseModel):
    role: str       # "user" or "assistant"
    content: str


class CipherChatRequest(BaseModel):
    messages: list[ChatMessage]
    sample_id: Optional[str] = None    # if set, inject analysis context


class CipherChatResponse(BaseModel):
    reply: str


class ExplainRequest(BaseModel):
    item_type: str        # e.g., "yara", "ioc", "mitre", "behavior"
    item_value: str       # e.g., "MAL_Ransomware...", "185.220.101.47"
    context: Optional[str] = None

class ExplainResponse(BaseModel):
    explanation: str


# ── Stats / Dashboard schemas ────────────────────────────────────
class DashboardStats(BaseModel):
    total_files_analyzed: int
    active_cases: int
    total_threats_found: int
    total_iocs_extracted: int
    files_today: int
    threats_today: int


# ── Audit log schemas ─────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    action: str
    actor: str
    details: str
    timestamp: datetime

    class Config:
        from_attributes = True
