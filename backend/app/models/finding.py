import uuid
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime, UUID, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.session import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="informational")  # critical, high, medium, low, informational
    status = Column(String, nullable=False, default="open")             # open, confirmed, false_positive, remediated, accepted_risk
    target = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    service = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    source_tool = Column(String, nullable=False)                       # Nmap, Nuclei, Nikto, Subfinder, DNS, theHarvester, Shodan, Web Application Testing
    source_scan_id = Column(UUID(as_uuid=True), nullable=True)
    fingerprint = Column(String, nullable=False, index=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
