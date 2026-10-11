from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID

class OsintNoteCreate(BaseModel):
    author: Optional[str] = "OSINT Researcher"
    note: str = Field(..., min_length=1)

class OsintNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    investigation_id: UUID
    author: str
    note: str
    created_at: datetime

class OsintRecordCreate(BaseModel):
    tool: str
    record_type: str
    data: Any
    source_url: Optional[str] = None
    is_live: bool = True

class OsintRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    investigation_id: UUID
    tool: str
    record_type: str
    data: Any
    source_url: Optional[str] = None
    collection_timestamp: datetime
    is_live: bool
    created_at: datetime

class OsintInvestigationCreate(BaseModel):
    title: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    target_type: str = "domain"  # domain, ip, organization
    scope_description: Optional[str] = None
    investigation_purpose: str = Field(..., min_length=3, description="Legitimate authorized investigation purpose")
    authorization_confirmed: bool = Field(..., description="Must be confirmed for active reconnaissance")

class OsintInvestigationUpdate(BaseModel):
    title: Optional[str] = None
    scope_description: Optional[str] = None
    investigation_purpose: Optional[str] = None
    status: Optional[str] = None  # active, completed, archived

class OsintInvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    title: str
    target: str
    target_type: str
    scope_description: Optional[str] = None
    investigation_purpose: str
    authorization_confirmed: bool
    status: str
    created_at: datetime
    updated_at: datetime
    records_count: int = 0
    records: List[OsintRecordResponse] = []
    notes: List[OsintNoteResponse] = []

class OsintScanActionRequest(BaseModel):
    tool: str = Field(..., description="subfinder, dns, theharvester, shodan, whois_rdap")
    authorization_confirmed: bool = True
