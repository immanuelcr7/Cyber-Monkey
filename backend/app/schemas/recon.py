from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID

from app.schemas.target import TargetResponse

class NmapPortResponse(BaseModel):
    id: UUID
    scan_id: UUID
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class NmapScanCreate(BaseModel):
    target_id: UUID
    scan_profile: str = Field(..., description="Scan profile: host_discovery, basic_port, service_detection, comprehensive")

class NmapScanResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    target_id: UUID
    scan_profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    raw_output: Optional[str] = None
    error_output: Optional[str] = None
    created_at: datetime
    ports: List[NmapPortResponse] = []
    target: Optional[TargetResponse] = None

    class Config:
        from_attributes = True

class NmapStatusResponse(BaseModel):
    installed: bool
    version: Optional[str] = None


class SubdomainResponse(BaseModel):
    id: UUID
    scan_id: UUID
    subdomain: str
    created_at: datetime

    class Config:
        from_attributes = True


class SubfinderScanCreate(BaseModel):
    target_id: UUID


class SubfinderScanResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    target_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    raw_output: Optional[str] = None
    error_output: Optional[str] = None
    created_at: datetime
    subdomains: List[SubdomainResponse] = []
    target: Optional[TargetResponse] = None

    class Config:
        from_attributes = True


class SubfinderStatusResponse(BaseModel):
    installed: bool
    version: Optional[str] = None


class DnsRecordResponse(BaseModel):
    id: UUID
    scan_id: UUID
    record_type: str
    name: str
    value: str
    ttl: int
    created_at: datetime

    class Config:
        from_attributes = True


class DnsScanCreate(BaseModel):
    target_id: UUID


class DnsScanResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    target_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    error_output: Optional[str] = None
    created_at: datetime
    records: List[DnsRecordResponse] = []
    target: Optional[TargetResponse] = None

    class Config:
        from_attributes = True


class DnsStatusResponse(BaseModel):
    available: bool
    resolver: str


class TheHarvesterEmailResponse(BaseModel):
    id: UUID
    scan_id: UUID
    email: str
    source: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TheHarvesterHostResponse(BaseModel):
    id: UUID
    scan_id: UUID
    hostname: str
    ip: Optional[str] = None
    source: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TheHarvesterIpResponse(BaseModel):
    id: UUID
    scan_id: UUID
    ip: str
    source: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TheHarvesterNameResponse(BaseModel):
    id: UUID
    scan_id: UUID
    name: str
    source: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TheHarvesterScanCreate(BaseModel):
    target_id: UUID


class TheHarvesterScanResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    target_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    return_code: Optional[int] = None
    emails_found: int
    hosts_found: int
    ips_found: int
    names_found: int
    raw_output: Optional[str] = None
    error_output: Optional[str] = None
    created_at: datetime
    emails: List[TheHarvesterEmailResponse] = []
    hosts: List[TheHarvesterHostResponse] = []
    ips: List[TheHarvesterIpResponse] = []
    names: List[TheHarvesterNameResponse] = []
    target: Optional[TargetResponse] = None

    class Config:
        from_attributes = True


class TheHarvesterStatusResponse(BaseModel):
    available: bool
    path: str
    version: Optional[str] = None



# ============================================================
# Shodan Public Intelligence Schemas
# ============================================================

class ShodanStatusResponse(BaseModel):
    configured: bool
    available: bool


class ShodanScanCreate(BaseModel):
    target_id: UUID


class ShodanServiceResponse(BaseModel):
    id: UUID
    host_id: UUID
    port: int
    transport: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ShodanVulnerabilityResponse(BaseModel):
    id: UUID
    host_id: UUID
    cve: str
    source: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ShodanHostResponse(BaseModel):
    id: UUID
    scan_id: UUID
    ip: str
    hostname: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    created_at: datetime
    services: List[ShodanServiceResponse] = []
    vulnerabilities: List[ShodanVulnerabilityResponse] = []

    class Config:
        from_attributes = True


class ShodanScanResponse(BaseModel):
    id: UUID
    assessment_id: UUID
    target_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    error_output: Optional[str] = None
    created_at: datetime
    hosts: List[ShodanHostResponse] = []
    target: Optional[TargetResponse] = None

    class Config:
        from_attributes = True
