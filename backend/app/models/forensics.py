import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Integer, Boolean, ForeignKey, DateTime, UUID
from sqlalchemy.orm import relationship
from app.database.session import Base

class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number = Column(String, unique=True, nullable=False)  # e.g. DFIR-2026-001
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    investigator = Column(String, default="Forensic Analyst", nullable=False)
    priority = Column(String, default="medium", nullable=False)  # low, medium, high, critical
    status = Column(String, default="active", nullable=False)  # active, in_review, closed, archived
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    evidence = relationship("ForensicEvidence", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("ForensicTimelineEvent", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("ForensicNote", back_populates="case", cascade="all, delete-orphan")


class ForensicEvidence(Base):
    __tablename__ = "forensic_evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False)
    evidence_identifier = Column(String, nullable=False)  # e.g. ITEM-001
    original_filename = Column(String, nullable=False)
    storage_identifier = Column(String, nullable=False)  # UUID storage filename
    media_type = Column(String, default="log_file", nullable=False)  # disk_image, memory_dump, log_file, pcap, filesystem_triage, other
    file_size = Column(Integer, nullable=False)
    source_location = Column(String, nullable=False)  # e.g. "Workstation WS-04, C:\Windows\System32\winevt\Logs"
    collector_name = Column(String, nullable=False)
    acquisition_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    acquisition_sha256 = Column(String(64), nullable=False)
    last_verified_sha256 = Column(String(64), nullable=True)
    last_verification_timestamp = Column(DateTime, nullable=True)
    verification_status = Column(String, default="VERIFIED", nullable=False)  # VERIFIED, TAMPERED, FILE_NOT_FOUND, UNVERIFIED
    read_only_status = Column(Boolean, default=True, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("ForensicCase", back_populates="evidence")
    chain_of_custody = relationship("ChainOfCustody", back_populates="evidence", cascade="all, delete-orphan")


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("forensic_evidence.id", ondelete="CASCADE"), nullable=False)
    action = Column(String, nullable=False)  # ACQUISITION, INTEGRITY_VERIFICATION, TRIAGE_ANALYSIS, CUSTODY_TRANSFER, SECURE_STORAGE
    performed_by = Column(String, nullable=False)
    location = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    reason = Column(Text, nullable=False)
    verified_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    evidence = relationship("ForensicEvidence", back_populates="chain_of_custody")


class ForensicTimelineEvent(Base):
    __tablename__ = "forensic_timeline_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    event_source = Column(String, nullable=False)  # Auth Log, Registry, File System, Network, Process Execution
    source_host = Column(String, nullable=True)
    user_account = Column(String, nullable=True)
    event_description = Column(Text, nullable=False)
    severity = Column(String, default="info", nullable=False)  # info, low, medium, high, critical
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("forensic_evidence.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("ForensicCase", back_populates="timeline_events")


class ForensicNote(Base):
    __tablename__ = "forensic_notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False)
    author = Column(String, default="Forensic Investigator", nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    case = relationship("ForensicCase", back_populates="notes")
