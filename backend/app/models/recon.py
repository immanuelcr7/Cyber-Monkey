import uuid
from sqlalchemy import Column, String, Text, Integer, Float, ForeignKey, DateTime, UUID, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.session import Base

class NmapScan(Base):
    __tablename__ = "nmap_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_profile = Column(String, nullable=False)  # host_discovery, basic_port, service_detection, comprehensive
    status = Column(String, nullable=False)        # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    raw_output = Column(Text, nullable=True)
    error_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
    target = relationship("Target")
    ports = relationship("NmapPort", back_populates="scan", cascade="all, delete-orphan")

class NmapPort(Base):
    __tablename__ = "nmap_ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("nmap_scans.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    state = Column(String, nullable=False)
    service = Column(String, nullable=True)
    version = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("NmapScan", back_populates="ports")


class SubfinderScan(Base):
    __tablename__ = "subfinder_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)        # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    raw_output = Column(Text, nullable=True)
    error_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
    target = relationship("Target")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("subfinder_scans.id", ondelete="CASCADE"), nullable=False)
    subdomain = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("SubfinderScan", back_populates="subdomains")


class DnsScan(Base):
    __tablename__ = "dns_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)        # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    error_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
    target = relationship("Target")
    records = relationship("DnsRecord", back_populates="scan", cascade="all, delete-orphan")


class DnsRecord(Base):
    __tablename__ = "dns_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("dns_scans.id", ondelete="CASCADE"), nullable=False)
    record_type = Column(String, nullable=False)
    name = Column(String, nullable=False)
    value = Column(String, nullable=False)
    ttl = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("DnsScan", back_populates="records")


class TheHarvesterScan(Base):
    __tablename__ = "theharvester_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)        # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    return_code = Column(Integer, nullable=True)
    emails_found = Column(Integer, default=0, nullable=False)
    hosts_found = Column(Integer, default=0, nullable=False)
    ips_found = Column(Integer, default=0, nullable=False)
    names_found = Column(Integer, default=0, nullable=False)
    raw_output = Column(Text, nullable=True)
    error_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
    target = relationship("Target")
    emails = relationship("TheHarvesterEmail", back_populates="scan", cascade="all, delete-orphan")
    hosts = relationship("TheHarvesterHost", back_populates="scan", cascade="all, delete-orphan")
    ips = relationship("TheHarvesterIp", back_populates="scan", cascade="all, delete-orphan")
    names = relationship("TheHarvesterName", back_populates="scan", cascade="all, delete-orphan")


class TheHarvesterEmail(Base):
    __tablename__ = "theharvester_emails"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("theharvester_scans.id", ondelete="CASCADE"), nullable=False)
    email = Column(String, nullable=False)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("TheHarvesterScan", back_populates="emails")


class TheHarvesterHost(Base):
    __tablename__ = "theharvester_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("theharvester_scans.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("TheHarvesterScan", back_populates="hosts")


class TheHarvesterIp(Base):
    __tablename__ = "theharvester_ips"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("theharvester_scans.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String, nullable=False)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("TheHarvesterScan", back_populates="ips")


class TheHarvesterName(Base):
    __tablename__ = "theharvester_names"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("theharvester_scans.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("TheHarvesterScan", back_populates="names")


# ============================================================
# Shodan Public Intelligence Models
# ============================================================

class ShodanScan(Base):
    __tablename__ = "shodan_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)        # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    error_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment")
    target = relationship("Target")
    hosts = relationship("ShodanHost", back_populates="scan", cascade="all, delete-orphan")


class ShodanHost(Base):
    __tablename__ = "shodan_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("shodan_scans.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    source = Column(String, default="shodan", nullable=False)
    cpes = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)
    domains = Column(JSON, nullable=True)
    # Raw Shodan API response stored as JSON for evidence/audit (no credentials stored)
    raw_response = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("ShodanScan", back_populates="hosts")
    services = relationship("ShodanService", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("ShodanVulnerability", back_populates="host", cascade="all, delete-orphan")



class ShodanService(Base):
    __tablename__ = "shodan_services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("shodan_hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    transport = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    service = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    host = relationship("ShodanHost", back_populates="services")


class ShodanVulnerability(Base):
    __tablename__ = "shodan_vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("shodan_hosts.id", ondelete="CASCADE"), nullable=False)
    cve = Column(String, nullable=False)
    source = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    host = relationship("ShodanHost", back_populates="vulnerabilities")
