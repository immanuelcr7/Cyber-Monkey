from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID

class NetworkServiceCreate(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: str = "TCP"
    service_name: Optional[str] = "unknown"
    banner: Optional[str] = None
    status: str = "open"

class NetworkServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_id: UUID
    port: int
    protocol: str
    service_name: str
    banner: Optional[str] = None
    status: str
    last_checked: datetime
    created_at: datetime

class NetworkEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_id: Optional[UUID] = None
    event_type: str
    severity: str
    message: str
    details: Optional[Any] = None
    timestamp: datetime
    created_at: datetime

class NetworkAssetCreate(BaseModel):
    ip_address: str = Field(..., min_length=1)
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: str = "server"
    monitored: bool = True
    check_interval_seconds: int = 60
    notes: Optional[str] = None
    ports: Optional[List[int]] = []

class NetworkAssetUpdate(BaseModel):
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: Optional[str] = None
    monitored: Optional[bool] = None
    notes: Optional[str] = None

class NetworkAssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: str
    status: str
    last_seen: datetime
    response_time_ms: Optional[float] = None
    monitored: bool
    check_interval_seconds: int
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    services: List[NetworkServiceResponse] = []

class NetworkCheckResult(BaseModel):
    asset_id: UUID
    ip_address: str
    status: str  # up, down
    response_time_ms: Optional[float] = None
    services_checked: int
    open_ports: List[int]
    timestamp: datetime
