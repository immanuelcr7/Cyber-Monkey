from pydantic import BaseModel, ConfigDict
from typing import Optional, Any
from datetime import datetime
from uuid import UUID

class IntegrationStatusResponse(BaseModel):
    name: str
    display_name: str
    is_configured: bool
    status: str  # connected, not_configured, error, disabled
    details: Optional[Any] = None
    last_health_check: Optional[datetime] = None
    error_message: Optional[str] = None

class AllIntegrationsStatusResponse(BaseModel):
    wazuh: IntegrationStatusResponse
    shodan: IntegrationStatusResponse
    nmap: IntegrationStatusResponse
    subfinder: IntegrationStatusResponse
    theharvester: IntegrationStatusResponse
    dns: IntegrationStatusResponse
    yara: IntegrationStatusResponse
    zeek: IntegrationStatusResponse
    suricata: IntegrationStatusResponse
    ai_assistant: IntegrationStatusResponse
