import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime, UUID, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class SocAlert(Base):
    __tablename__ = "soc_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(String, unique=True, nullable=False)  # e.g., external Wazuh ID or AL-XXXX
    rule_id = Column(String, nullable=False)
    rule_description = Column(Text, nullable=False)
    rule_level = Column(Integer, default=1, nullable=False)  # e.g. Wazuh rule level 1-15
    severity = Column(String, default="medium", nullable=False)  # low, medium, high, critical
    status = Column(String, default="new", nullable=False)  # new, in_triage, investigating, contained, closed, false_positive
    source = Column(String, default="Wazuh", nullable=False)  # Wazuh, Suricata, EDR, Syslog, Manual
    host_name = Column(String, nullable=True)
    host_ip = Column(String, nullable=True)
    agent_id = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    raw_data = Column(JSON, nullable=True)
    evidence = Column(Text, nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("soc_incidents.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    incident = relationship("SocIncident", back_populates="alerts")
    notes = relationship("SocInvestigationNote", back_populates="alert", cascade="all, delete-orphan")


class SocIncident(Base):
    __tablename__ = "soc_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_number = Column(String, unique=True, nullable=False)  # e.g. INC-2026-0001
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="medium", nullable=False)  # low, medium, high, critical
    status = Column(String, default="open", nullable=False)  # open, investigating, contained, resolved, closed
    assigned_to = Column(String, nullable=True)
    category = Column(String, default="Unauthorized Access", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    alerts = relationship("SocAlert", back_populates="incident")
    notes = relationship("SocInvestigationNote", back_populates="incident", cascade="all, delete-orphan")


class SocInvestigationNote(Base):
    __tablename__ = "soc_investigation_notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("soc_alerts.id", ondelete="CASCADE"), nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("soc_incidents.id", ondelete="CASCADE"), nullable=True)
    author = Column(String, default="SOC Analyst", nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    alert = relationship("SocAlert", back_populates="notes")
    incident = relationship("SocIncident", back_populates="notes")


class SocAuditLog(Base):
    __tablename__ = "soc_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action = Column(String, nullable=False)  # e.g. STATUS_CHANGE, INCIDENT_CREATED, ALERT_TRIAGED
    performed_by = Column(String, default="analyst", nullable=False)
    target_type = Column(String, nullable=False)  # alert, incident
    target_id = Column(String, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
