import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, UUID, JSON
from app.database.session import Base

class SharedAuditLog(Base):
    __tablename__ = "shared_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace = Column(String, nullable=False)  # soc, osint, malware, forensics, network, pentest, ai
    action = Column(String, nullable=False)
    user = Column(String, default="operator", nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
