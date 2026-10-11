import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, UUID, JSON, Text
from app.database.session import Base

class IntegrationConfig(Base):
    __tablename__ = "integration_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)  # wazuh, shodan, zeek, suricata, yara, ai_assistant
    display_name = Column(String, nullable=False)
    is_configured = Column(Boolean, default=False, nullable=False)
    status = Column(String, default="not_configured", nullable=False)  # connected, not_configured, error, disabled
    config_metadata = Column(JSON, nullable=True)  # sanitized safe settings (URLs, versions, endpoints)
    last_health_check = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
