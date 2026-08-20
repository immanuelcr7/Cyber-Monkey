from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import date, datetime
from uuid import UUID
from app.schemas.target import TargetResponse

class AssessmentBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)
    assessment_type: str = Field(..., description="Assessment type: e.g. External Network, Internal Network, Web Application, API, Cloud, Other")
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: str = Field("active", description="Status: active, completed, archived")

class AssessmentCreate(AssessmentBase):
    pass

class AssessmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)
    assessment_type: Optional[str] = None
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = None

class AssessmentResponse(AssessmentBase):
    id: UUID
    created_at: datetime
    updated_at: datetime
    target_count: int = 0

    class Config:
        from_attributes = True

class AssessmentDetailResponse(AssessmentResponse):
    targets: List[TargetResponse] = []

    class Config:
        from_attributes = True
