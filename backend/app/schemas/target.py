from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID

class TargetBase(BaseModel):
    target_type: str = Field(..., description="Target type: Domain, IP Address, URL")
    target_value: str = Field(..., min_length=1)
    scope_status: str = Field("in_scope", description="Scope: in_scope, out_of_scope")
    authorization_confirmed: bool = Field(False)
    description: Optional[str] = None
    notes: Optional[str] = None

class TargetCreate(TargetBase):
    pass

class TargetUpdate(BaseModel):
    target_type: Optional[str] = None
    target_value: Optional[str] = Field(None, min_length=1)
    scope_status: Optional[str] = None
    authorization_confirmed: Optional[bool] = None
    description: Optional[str] = None
    notes: Optional[str] = None

class TargetResponse(TargetBase):
    id: UUID
    assessment_id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
