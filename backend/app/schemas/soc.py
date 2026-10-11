from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID

class SocInvestigationNoteCreate(BaseModel):
    author: Optional[str] = "SOC Analyst"
    note: str = Field(..., min_length=1)

class SocInvestigationNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    alert_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    author: str
    note: str
    created_at: datetime

class SocAlertCreate(BaseModel):
    alert_id: Optional[str] = None
    rule_id: str = Field(..., min_length=1)
    rule_description: str = Field(..., min_length=1)
    rule_level: int = 5
    severity: str = "medium"  # low, medium, high, critical
    source: str = "Manual / Wazuh"
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    agent_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_data: Optional[Any] = None
    evidence: Optional[str] = None

class SocAlertUpdate(BaseModel):
    status: Optional[str] = None  # new, in_triage, investigating, contained, closed, false_positive
    severity: Optional[str] = None
    incident_id: Optional[UUID] = None

class SocAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    alert_id: str
    rule_id: str
    rule_description: str
    rule_level: int
    severity: str
    status: str
    source: str
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    agent_id: Optional[str] = None
    timestamp: datetime
    raw_data: Optional[Any] = None
    evidence: Optional[str] = None
    incident_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    notes: List[SocInvestigationNoteResponse] = []

class SocIncidentCreate(BaseModel):
    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    assigned_to: Optional[str] = None
    category: str = "Unauthorized Access"
    alert_ids: Optional[List[UUID]] = []

class SocIncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None  # open, investigating, contained, resolved, closed
    assigned_to: Optional[str] = None
    category: Optional[str] = None

class SocIncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    incident_number: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[str] = None
    category: str
    created_at: datetime
    updated_at: datetime
    alerts: List[SocAlertResponse] = []
    notes: List[SocInvestigationNoteResponse] = []

class SocAuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    action: str
    performed_by: str
    target_type: str
    target_id: str
    details: Optional[Any] = None
    created_at: datetime

class WazuhConfigRequest(BaseModel):
    api_url: str
    username: str
    password: str
    verify_ssl: bool = False

class WazuhStatusResponse(BaseModel):
    configured: bool
    connected: bool
    api_url: Optional[str] = None
    version: Optional[str] = None
    message: str
    last_checked: Optional[datetime] = None
