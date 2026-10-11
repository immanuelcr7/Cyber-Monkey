import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Boolean, ForeignKey, DateTime, UUID, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class OsintInvestigation(Base):
    __tablename__ = "osint_investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    target = Column(String, nullable=False)
    target_type = Column(String, default="domain", nullable=False)  # domain, ip, organization
    scope_description = Column(Text, nullable=True)
    investigation_purpose = Column(Text, nullable=False)
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    status = Column(String, default="active", nullable=False)  # active, completed, archived
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    records = relationship("OsintRecord", back_populates="investigation", cascade="all, delete-orphan")
    notes = relationship("OsintNote", back_populates="investigation", cascade="all, delete-orphan")


class OsintRecord(Base):
    __tablename__ = "osint_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("osint_investigations.id", ondelete="CASCADE"), nullable=False)
    tool = Column(String, nullable=False)  # subfinder, dns, theharvester, shodan, whois_rdap, manual
    record_type = Column(String, nullable=False)  # subdomain, dns_record, email, ip, whois, shodan_host
    data = Column(JSON, nullable=False)
    source_url = Column(String, nullable=True)
    collection_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_live = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    investigation = relationship("OsintInvestigation", back_populates="records")


class OsintNote(Base):
    __tablename__ = "osint_notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("osint_investigations.id", ondelete="CASCADE"), nullable=False)
    author = Column(String, default="OSINT Researcher", nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    investigation = relationship("OsintInvestigation", back_populates="notes")
