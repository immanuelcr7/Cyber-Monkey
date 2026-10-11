from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID

class ForensicNoteCreate(BaseModel):
    author: Optional[str] = "Forensic Investigator"
    content: str = Field(..., min_length=1)

class ForensicNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_id: UUID
    author: str
    content: str
    created_at: datetime

class ChainOfCustodyCreate(BaseModel):
    action: str = Field(..., min_length=1)  # ACQUISITION, INTEGRITY_VERIFICATION, TRIAGE_ANALYSIS, CUSTODY_TRANSFER, SECURE_STORAGE
    performed_by: str = Field(..., min_length=1)
    location: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)

class ChainOfCustodyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    evidence_id: UUID
    action: str
    performed_by: str
    location: str
    timestamp: datetime
    reason: str
    verified_hash: Optional[str] = None
    created_at: datetime

class ForensicEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_id: UUID
    evidence_identifier: str
    original_filename: str
    storage_identifier: str
    media_type: str
    file_size: int
    source_location: str
    collector_name: str
    acquisition_timestamp: datetime
    acquisition_sha256: str
    last_verified_sha256: Optional[str] = None
    last_verification_timestamp: Optional[datetime] = None
    verification_status: str
    read_only_status: bool
    notes: Optional[str] = None
    created_at: datetime
    chain_of_custody: List[ChainOfCustodyResponse] = []

class ForensicTimelineEventCreate(BaseModel):
    timestamp: datetime
    event_source: str
    source_host: Optional[str] = None
    user_account: Optional[str] = None
    event_description: str
    severity: str = "info"  # info, low, medium, high, critical
    evidence_id: Optional[UUID] = None

class ForensicTimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_id: UUID
    timestamp: datetime
    event_source: str
    source_host: Optional[str] = None
    user_account: Optional[str] = None
    event_description: str
    severity: str
    evidence_id: Optional[UUID] = None
    created_at: datetime

class ForensicCaseCreate(BaseModel):
    case_number: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    investigator: str = "Forensic Analyst"
    priority: str = "medium"  # low, medium, high, critical

class ForensicCaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    investigator: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None  # active, in_review, closed, archived

class ForensicCaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_number: str
    title: str
    description: Optional[str] = None
    investigator: str
    priority: str
    status: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    evidence: List[ForensicEvidenceResponse] = []
    timeline_events: List[ForensicTimelineEventResponse] = []
    notes: List[ForensicNoteResponse] = []

class VerifyIntegrityResponse(BaseModel):
    evidence_id: UUID
    status: str  # VERIFIED, TAMPERED, FILE_NOT_FOUND
    acquisition_sha256: str
    computed_sha256: Optional[str] = None
    matches: bool
    verification_timestamp: datetime
    message: str
