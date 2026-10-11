import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Integer, Float, Boolean, ForeignKey, DateTime, UUID, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class NetworkAsset(Base):
    __tablename__ = "network_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    asset_type = Column(String, default="server", nullable=False)  # server, workstation, router, switch, firewall, iot, unknown
    status = Column(String, default="up", nullable=False)  # up, down, unknown
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    response_time_ms = Column(Float, nullable=True)
    monitored = Column(Boolean, default=True, nullable=False)
    check_interval_seconds = Column(Integer, default=60, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    services = relationship("NetworkService", back_populates="asset", cascade="all, delete-orphan")
    events = relationship("NetworkEvent", back_populates="asset", cascade="all, delete-orphan")


class NetworkService(Base):
    __tablename__ = "network_services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("network_assets.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="TCP", nullable=False)
    service_name = Column(String, default="unknown", nullable=False)
    banner = Column(String, nullable=True)
    status = Column(String, default="open", nullable=False)  # open, closed, filtered
    last_checked = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    asset = relationship("NetworkAsset", back_populates="services")


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("network_assets.id", ondelete="SET NULL"), nullable=True)
    event_type = Column(String, nullable=False)  # HOST_DOWN, HOST_UP, NEW_PORT_DISCOVERED, PORT_CLOSED, LATENCY_SPIKE, UNUSUAL_CHANGE
    severity = Column(String, default="low", nullable=False)  # low, medium, high, critical
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    asset = relationship("NetworkAsset", back_populates="events")


class NetworkMonitorConfig(Base):
    __tablename__ = "network_monitor_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, default="Default Monitoring Profile", nullable=False)
    ping_timeout_seconds = Column(Float, default=2.0, nullable=False)
    port_timeout_seconds = Column(Float, default=1.5, nullable=False)
    alert_on_host_down = Column(Boolean, default=True, nullable=False)
    alert_on_new_port = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
