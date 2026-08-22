import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
import uuid
from datetime import datetime
from fastapi.testclient import TestClient
import dns.resolver
import dns.exception

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.dns_service import check_dns_availability, execute_dns_scan
from app.models.recon import DnsScan, DnsRecord
from app.models.target import Target

@pytest.fixture(name="db")
def db_fixture():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        # Safely remove test database file after run
        if os.path.exists("./test.db"):
            try:
                os.remove("./test.db")
            except Exception:
                pass

@pytest.fixture(name="client")
def client_fixture(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# Mock classes to mimic dnspython outputs
class MockExchange:
    def __init__(self, host):
        self.host = host
    def to_text(self):
        return self.host

class MockTarget:
    def __init__(self, target):
        self.target = target
    def to_text(self):
        return self.target

class MockMXRecord:
    def __init__(self, preference, exchange_host):
        self.preference = preference
        self.exchange = MockExchange(exchange_host)
    def to_text(self):
        return f"{self.preference} {self.exchange.to_text()}"

class MockNSRecord:
    def __init__(self, target_host):
        self.target = MockTarget(target_host)
    def to_text(self):
        return self.target.to_text()

class MockCNAMERecord:
    def __init__(self, target_host):
        self.target = MockTarget(target_host)
    def to_text(self):
        return self.target.to_text()

class MockTXTRecord:
    def __init__(self, strings):
        self.strings = strings # list of bytes e.g. [b"v=spf1"]
    def to_text(self):
        return b" ".join(self.strings).decode('utf-8')

class MockGenericRecord:
    def __init__(self, value):
        self.value = value
    def to_text(self):
        return self.value

class MockAnswer:
    def __init__(self, rdata_list, ttl=300):
        self.rdata_list = rdata_list
        self.ttl = ttl
    def __iter__(self):
        return iter(self.rdata_list)


# 1. DNS availability status check tests
@patch("dns.resolver.Resolver")
def test_check_dns_availability_success(mock_resolver_class):
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.nameservers = ["1.1.1.1"]
    mock_resolver_class.return_value = mock_resolver_instance
    
    available, resolver, detail = check_dns_availability()
    assert available is True
    assert resolver == "1.1.1.1"
    assert "fully functional" in detail

@patch("dns.resolver.Resolver")
def test_check_dns_availability_failure(mock_resolver_class):
    mock_resolver_class.side_effect = Exception("Resolver initialization failed")
    
    available, resolver, detail = check_dns_availability()
    assert available is False
    assert resolver is None
    assert "failed" in detail


# 2. DNS scan execution tests with mock resolver
@patch("dns.resolver.Resolver.resolve")
def test_execute_dns_scan_success(mock_resolve):
    def side_effect(qname, rdtype, *args, **kwargs):
        if rdtype == "A":
            return MockAnswer([MockGenericRecord("1.2.3.4")])
        elif rdtype == "AAAA":
            return MockAnswer([MockGenericRecord("2001:db8::1")])
        elif rdtype == "MX":
            return MockAnswer([MockMXRecord(10, "mail.example.com")])
        elif rdtype == "NS":
            return MockAnswer([MockNSRecord("ns1.example.com")])
        elif rdtype == "CNAME":
            # apex domain might not have cname
            raise dns.resolver.NoAnswer()
        elif rdtype == "TXT":
            return MockAnswer([MockTXTRecord([b"v=spf1", b"include:_spf.google.com"])])
        elif rdtype == "SOA":
            return MockAnswer([MockGenericRecord("ns1.example.com. hostmaster.example.com. 2023010101 7200 3600 1209600 3600")])
        raise dns.resolver.NoAnswer()
        
    mock_resolve.side_effect = side_effect
    
    result = execute_dns_scan("example.com")
    assert result["status"] == "completed"
    assert result["error_output"] is None
    assert result["duration"] >= 0
    
    records = result["records"]
    assert len(records) > 0
    
    # Check individual records
    a_rec = next(r for r in records if r["record_type"] == "A")
    assert a_rec["value"] == "1.2.3.4"
    assert a_rec["ttl"] == 300
    
    mx_rec = next(r for r in records if r["record_type"] == "MX")
    assert mx_rec["value"] == "10 mail.example.com"
    
    txt_rec = next(r for r in records if r["record_type"] == "TXT")
    assert txt_rec["value"] == "v=spf1 include:_spf.google.com"


# 3. DNS scan timeout handling test
@patch("dns.resolver.Resolver.resolve")
def test_execute_dns_scan_timeout(mock_resolve):
    mock_resolve.side_effect = dns.exception.Timeout()
    
    result = execute_dns_scan("example.com")
    assert result["status"] == "failed"
    assert "timed out" in result["error_output"]
    assert len(result["records"]) == 0


# 4. DNS scan NXDOMAIN handling test
@patch("dns.resolver.Resolver.resolve")
def test_execute_dns_scan_nxdomain(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()
    
    result = execute_dns_scan("nonexistent.example.com")
    assert result["status"] == "failed"
    assert "not found (NXDOMAIN)" in result["error_output"]
    assert len(result["records"]) == 0


# 5. Router endpoints & database persistence validation
def test_dns_status_endpoint(client):
    with patch("app.api.routes.recon.check_dns_availability") as mock_avail:
        mock_avail.return_value = (True, "8.8.8.8", "DNS resolution is fully functional.")
        
        response = client.get("/api/recon/dns/status")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is True
        assert data["resolver"] == "8.8.8.8"


def test_scan_dns_successful_and_stored(client, db):
    # Create assessment
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Internal Network"})
    a_id = a_res.json()["id"]
    
    # Create target
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="testdomain.com",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    with patch("app.api.routes.recon.execute_dns_scan") as mock_exec, \
         patch("app.api.routes.recon.check_dns_availability") as mock_avail:
        mock_avail.return_value = (True, "8.8.8.8", "DNS resolution is fully functional.")
        mock_exec.return_value = {
            "status": "completed",
            "error_output": None,
            "duration": 0.45,
            "records": [
                {"record_type": "A", "name": "testdomain.com", "value": "1.1.1.1", "ttl": 300},
                {"record_type": "MX", "name": "testdomain.com", "value": "10 mail.testdomain.com", "ttl": 600}
            ]
        }
        
        response = client.post(
            f"/api/assessments/{a_id}/recon/dns",
            json={"target_id": str(t.id)}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["duration"] == 0.45
        assert len(data["records"]) == 2
        assert data["records"][0]["record_type"] == "A"
        assert data["records"][0]["value"] == "1.1.1.1"
        assert data["records"][1]["record_type"] == "MX"
        assert data["records"][1]["value"] == "10 mail.testdomain.com"
        
        # Verify db relationships & persistence
        dns_scan = db.query(DnsScan).filter(DnsScan.id == uuid.UUID(data["id"])).first()
        assert dns_scan is not None
        assert dns_scan.target_id == t.id
        assert len(dns_scan.records) == 2
        assert dns_scan.records[0].record_type == "A"
        assert dns_scan.records[0].value == "1.1.1.1"
        assert dns_scan.records[0].scan_id == dns_scan.id
        
        # Verify history works
        history_res = client.get(f"/api/assessments/{a_id}/recon/dns")
        assert history_res.status_code == 200
        history_data = history_res.json()
        assert len(history_data) == 1
        assert history_data[0]["id"] == data["id"]
        assert len(history_data[0]["records"]) == 2


def test_scan_reject_ip_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="8.8.8.8",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "only applicable to Domain targets" in response.json()["detail"]


def test_scan_reject_ip_string_as_domain_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    # Target claims to be Domain, but target_value is an IP address
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="8.8.8.8",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "IP address targets are not allowed" in response.json()["detail"]


def test_scan_reject_url_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="URL",
        target_value="https://example.com",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "only applicable to Domain targets" in response.json()["detail"]


def test_scan_reject_url_string_as_domain_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    # Target claims to be Domain, but target_value is a URL
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="https://example.com/site",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "URL targets are not allowed" in response.json()["detail"]


def test_scan_reject_unauthorized_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="unauthorized.com",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "not authorized" in response.json()["detail"]


def test_scan_reject_out_of_scope_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="outofscope.com",
        scope_status="out_of_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    response = client.post(
        f"/api/assessments/{a_id}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "out of scope" in response.json()["detail"]


def test_scan_reject_target_from_another_assessment(client, db):
    # Assessment 1
    a_res1 = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "External Network"})
    a_id1 = a_res1.json()["id"]
    
    # Assessment 2
    a_res2 = client.post("/api/assessments/", json={"name": "A2", "assessment_type": "External Network"})
    a_id2 = a_res2.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id1),
        target_type="Domain",
        target_value="example.com",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    # Try calling endpoint for Assessment 2, using Target from Assessment 1
    response = client.post(
        f"/api/assessments/{a_id2}/recon/dns",
        json={"target_id": str(t.id)}
    )
    assert response.status_code == 400
    assert "does not belong to the requested assessment" in response.json()["detail"]
