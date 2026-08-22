import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["SHODAN_API_KEY"] = "TEST_SHODAN_KEY_DO_NOT_EXPOSE"

import pytest
from unittest.mock import patch, MagicMock
import uuid
import socket
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.shodan_service import (
    check_shodan_status,
    resolve_target_to_ips,
    execute_shodan_lookup,
    _normalize_host_response,
)
from app.models.recon import ShodanScan, ShodanHost, ShodanService, ShodanVulnerability
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


def _create_assessment(client, name="Test Assessment"):
    """Helper: creates an assessment, accepts 200 or 201."""
    res = client.post("/api/assessments/", json={"name": name, "assessment_type": "Web Application"})
    assert res.status_code in (200, 201), f"Create assessment failed: {res.status_code} {res.text}"
    return res.json()["id"]


def _create_target(client, a_id, target_type="IP Address", target_value="93.184.216.34",
                   scope_status="in_scope", authorization_confirmed=True):
    """Helper: creates a target, accepts 200 or 201."""
    res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": target_type,
            "target_value": target_value,
            "scope_status": scope_status,
            "authorization_confirmed": authorization_confirmed,
        }
    )
    assert res.status_code in (200, 201), f"Create target failed: {res.status_code} {res.text}"
    return res.json()["id"]


# ============================================================
# 1. Shodan configuration status — key present and API valid
# ============================================================

def test_shodan_status_configured_and_available():
    """API key is set and api.info() succeeds → configured=True, available=True."""
    import shodan as real_shodan

    mock_api_instance = MagicMock()
    mock_api_instance.info.return_value = {"plan": "edu", "https": True}

    with patch("app.services.shodan_service._get_api_key", return_value="VALID_KEY"):
        with patch("app.services.shodan_service.shodan") as mock_shodan_mod:
            mock_shodan_mod.Shodan.return_value = mock_api_instance
            mock_shodan_mod.APIError = real_shodan.APIError

            result = check_shodan_status()

    assert result["configured"] is True
    assert result["available"] is True
    # API key must never be in the result
    assert "VALID_KEY" not in str(result)


def test_shodan_status_endpoint_returns_correct_schema(client):
    """GET /api/recon/shodan/status returns only configured and available fields."""
    with patch("app.api.routes.recon.check_shodan_status",
               return_value={"configured": True, "available": True}):
        response = client.get("/api/recon/shodan/status")
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is True
    assert data["available"] is True
    # Key must NEVER appear in the response
    assert "api_key" not in str(data)
    assert "TEST_SHODAN_KEY_DO_NOT_EXPOSE" not in response.text


# ============================================================
# 2. Missing API key
# ============================================================

def test_shodan_status_missing_api_key():
    """SHODAN_API_KEY is None → configured=False, available=False."""
    with patch("app.services.shodan_service._get_api_key", return_value=None):
        result = check_shodan_status()
    assert result["configured"] is False
    assert result["available"] is False


def test_shodan_status_endpoint_no_key(client):
    """GET /api/recon/shodan/status with missing key returns configured=False."""
    with patch("app.api.routes.recon.check_shodan_status",
               return_value={"configured": False, "available": False}):
        response = client.get("/api/recon/shodan/status")
    assert response.status_code == 200
    data = response.json()
    assert data["configured"] is False
    assert data["available"] is False
    assert "TEST_SHODAN_KEY_DO_NOT_EXPOSE" not in response.text


# ============================================================
# 3. Invalid API key handling
# ============================================================

def test_shodan_status_invalid_api_key():
    """api.info() raises 'Invalid API key' → configured=True, available=False."""
    import shodan as real_shodan

    mock_api_instance = MagicMock()
    mock_api_instance.info.side_effect = Exception("Invalid API key. Access denied.")

    with patch("app.services.shodan_service._get_api_key", return_value="INVALID_KEY"):
        with patch("app.services.shodan_service.shodan") as mock_shodan_mod:
            mock_shodan_mod.Shodan.return_value = mock_api_instance
            mock_shodan_mod.APIError = real_shodan.APIError

            result = check_shodan_status()

    assert result["configured"] is True
    assert result["available"] is False


# ============================================================
# 4. Authorized IP target — full lookup success
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_shodan_scan_authorized_ip(mock_status, mock_lookup, client):
    """POST scan with authorized IP target completes and stores results."""
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "completed",
        "duration": 1.5,
        "error_output": None,
        "hosts": [
            {
                "ip": "93.184.216.34",
                "hostname": "example.com",
                "organization": "EDGECAST",
                "isp": "MCI Communications Services",
                "country": "United States",
                "city": "Los Angeles",
                "latitude": 34.0522,
                "longitude": -118.2437,
                "raw_response": {"ip_str": "93.184.216.34", "org": "EDGECAST"},
                "services": [
                    {"port": 80, "transport": "tcp", "product": "Apache",
                     "version": "2.4", "service": "http", "banner": "HTTP/1.1 200 OK"},
                    {"port": 443, "transport": "tcp", "product": "Apache",
                     "version": "2.4", "service": "https", "banner": ""},
                ],
                "vulnerabilities": [
                    {"cve": "CVE-2021-41773", "source": "shodan",
                     "description": "Path traversal vulnerability"}
                ],
                "no_data": False,
            }
        ],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_type="IP Address", target_value="93.184.216.34")
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "completed"
    assert data["target_id"] == t_id
    assert data["assessment_id"] == a_id
    assert len(data["hosts"]) == 1
    host = data["hosts"][0]
    assert host["ip"] == "93.184.216.34"
    assert host["organization"] == "EDGECAST"
    assert host["country"] == "United States"
    assert len(host["services"]) == 2
    assert host["services"][0]["port"] == 80
    assert len(host["vulnerabilities"]) == 1
    assert host["vulnerabilities"][0]["cve"] == "CVE-2021-41773"
    # API key must not appear
    assert "TEST_SHODAN_KEY_DO_NOT_EXPOSE" not in response.text


# ============================================================
# 5. Authorized domain target
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_shodan_scan_authorized_domain(mock_status, mock_lookup, client):
    """POST scan with authorized Domain target completes successfully."""
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "completed",
        "duration": 2.0,
        "error_output": None,
        "hosts": [
            {
                "ip": "93.184.216.34",
                "hostname": "example.com",
                "organization": "EDGECAST",
                "isp": "Verizon Business",
                "country": "United States",
                "city": "Los Angeles",
                "latitude": 34.05,
                "longitude": -118.24,
                "raw_response": {},
                "services": [{"port": 443, "transport": "tcp", "product": None,
                               "version": None, "service": "https", "banner": ""}],
                "vulnerabilities": [],
                "no_data": False,
            }
        ],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_type="Domain", target_value="example.com")
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "completed"
    # Backend must pass target_type="Domain" and target_value="example.com" to service
    # (not an arbitrary IP from the frontend)
    mock_lookup.assert_called_once_with("Domain", "example.com")


# ============================================================
# 6. Out-of-scope target rejection
# ============================================================

def test_shodan_scan_out_of_scope_target(client):
    """Target with scope_status='out_of_scope' must be rejected."""
    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_type="IP Address", target_value="1.2.3.4",
                           scope_status="out_of_scope", authorization_confirmed=True)
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})
    assert response.status_code == 400
    assert "out of scope" in response.json()["detail"]


# ============================================================
# 7. Unauthorized target rejection
# ============================================================

def test_shodan_scan_unauthorized_target(client, db):
    """Target with authorization_confirmed=False must be rejected."""
    a_id = _create_assessment(client)
    # Insert unauthorized target directly into DB (API prevents in-scope+unauthorized combos)
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="1.2.3.4",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(t)
    db.commit()
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": str(t.id)})
    assert response.status_code == 400
    assert "not authorized" in response.json()["detail"]


# ============================================================
# 8. Target belonging to another assessment
# ============================================================

def test_shodan_scan_target_belongs_to_another_assessment(client):
    """Using a target from assessment A in assessment B must be rejected."""
    a_id = _create_assessment(client, name="Assessment A")
    t_id = _create_target(client, a_id, target_type="IP Address", target_value="10.0.0.1")

    b_id = _create_assessment(client, name="Assessment B")

    response = client.post(f"/api/assessments/{b_id}/recon/shodan", json={"target_id": t_id})
    assert response.status_code == 400
    assert "does not belong to the requested assessment" in response.json()["detail"]


# ============================================================
# 9. Shodan API error handling
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_shodan_scan_api_error(mock_status, mock_lookup, client):
    """Shodan API errors result in a failed scan stored in DB, not a server crash."""
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "failed",
        "duration": 0.5,
        "error_output": "Shodan API error: Too many requests",
        "hosts": [],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id)
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "failed"
    assert len(data["hosts"]) == 0


# ============================================================
# 10. Rate limit handling
# ============================================================

def test_shodan_rate_limit_in_service():
    """execute_shodan_lookup handles rate limit errors and returns failed status."""
    import shodan as real_shodan

    mock_api_instance = MagicMock()
    mock_api_instance.host.side_effect = real_shodan.APIError("rate limit reached")

    with patch("app.services.shodan_service._get_api_key", return_value="VALID_KEY"):
        with patch("app.services.shodan_service.resolve_target_to_ips",
                   return_value=(["1.2.3.4"], None)):
            with patch("app.services.shodan_service.shodan") as mock_shodan_mod:
                mock_shodan_mod.Shodan.return_value = mock_api_instance
                mock_shodan_mod.APIError = real_shodan.APIError
                # The rate limit comes from the host() call which raises APIError
                # but since shodan.APIError is mocked, the except clause catches Exception
                # Let's patch directly to test the error propagation path
                mock_api_instance.host.side_effect = real_shodan.APIError("rate limit reached")

                result = execute_shodan_lookup("IP Address", "1.2.3.4")

    assert result["status"] == "failed"
    assert "rate limit" in result["error_output"].lower()


# ============================================================
# 11. Response parsing — _normalize_host_response
# ============================================================

def test_shodan_response_parsing():
    """The service correctly normalizes a Shodan host API response."""
    raw = {
        "ip_str": "1.2.3.4",
        "hostnames": ["test.example.com"],
        "org": "Test Org",
        "isp": "Test ISP",
        "asn": "AS12345",
        "location": {
            "country_name": "Germany",
            "city": "Berlin",
            "latitude": 52.52,
            "longitude": 13.41,
        },
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "8.9",
                "_shodan": {"module": "ssh"},
                "data": "SSH-2.0-OpenSSH_8.9",
            }
        ],
        "vulns": {
            "CVE-2023-38408": {
                "summary": "Remote code execution in OpenSSH agent",
            }
        },
        "ports": [22],
        "tags": [],
        "last_update": "2024-01-01T00:00:00.000Z",
    }

    result = _normalize_host_response("1.2.3.4", raw)

    assert result["ip"] == "1.2.3.4"
    assert result["hostname"] == "test.example.com"
    assert result["organization"] == "Test Org"
    assert result["isp"] == "Test ISP"
    assert result["country"] == "Germany"
    assert result["city"] == "Berlin"
    assert result["latitude"] == 52.52
    assert result["longitude"] == 13.41
    assert len(result["services"]) == 1
    assert result["services"][0]["port"] == 22
    assert result["services"][0]["product"] == "OpenSSH"
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-2023-38408"
    assert result["vulnerabilities"][0]["description"] == "Remote code execution in OpenSSH agent"
    # Verify raw_response does NOT contain any API key
    assert "TEST_SHODAN_KEY_DO_NOT_EXPOSE" not in str(result["raw_response"])
    assert "api_key" not in str(result["raw_response"])


# ============================================================
# 12. Database persistence
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_shodan_scan_database_persistence(mock_status, mock_lookup, client, db):
    """Scan results are correctly persisted in the database with proper relationships."""
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "completed",
        "duration": 1.0,
        "error_output": None,
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostname": "internal.test",
                "organization": "Test Corp",
                "isp": "Test ISP",
                "country": "US",
                "city": "NYC",
                "latitude": 40.71,
                "longitude": -74.00,
                "raw_response": {"ip_str": "10.0.0.1"},
                "services": [
                    {"port": 8080, "transport": "tcp", "product": None,
                     "version": None, "service": "http-alt", "banner": ""},
                ],
                "vulnerabilities": [
                    {"cve": "CVE-2022-1234", "source": "shodan", "description": "Test vuln"}
                ],
                "no_data": False,
            }
        ],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_value="10.0.0.1")
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})
    assert response.status_code == 200, response.text
    scan_id = response.json()["id"]

    # Verify database records
    db_scan = db.query(ShodanScan).filter(ShodanScan.id == uuid.UUID(scan_id)).first()
    assert db_scan is not None
    assert db_scan.status == "completed"
    assert db_scan.target_id == uuid.UUID(t_id)
    assert db_scan.assessment_id == uuid.UUID(a_id)

    db_host = db.query(ShodanHost).filter(ShodanHost.scan_id == db_scan.id).first()
    assert db_host is not None
    assert db_host.ip == "10.0.0.1"
    assert db_host.organization == "Test Corp"

    db_service = db.query(ShodanService).filter(ShodanService.host_id == db_host.id).first()
    assert db_service is not None
    assert db_service.port == 8080

    db_vuln = db.query(ShodanVulnerability).filter(ShodanVulnerability.host_id == db_host.id).first()
    assert db_vuln is not None
    assert db_vuln.cve == "CVE-2022-1234"


# ============================================================
# 13. Correct scan-to-target relationship
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_shodan_history_correct_target_relationship(mock_status, mock_lookup, client):
    """Shodan history returns each scan with its correct target relationship."""
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "completed", "duration": 0.8, "error_output": None,
        "hosts": [],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_type="Domain", target_value="example.org")
    client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})

    history_res = client.get(f"/api/assessments/{a_id}/recon/shodan")
    assert history_res.status_code == 200
    data = history_res.json()
    assert len(data) == 1
    assert data[0]["target"]["target_value"] == "example.org"
    assert data[0]["target"]["target_type"] == "Domain"
    assert data[0]["target_id"] == t_id


# ============================================================
# 14. API key NEVER appears in any response
# ============================================================

@patch("app.api.routes.recon.execute_shodan_lookup")
@patch("app.api.routes.recon.check_shodan_status")
def test_api_key_never_in_response(mock_status, mock_lookup, client):
    """The Shodan API key must never appear in any API response."""
    test_key = "TEST_SHODAN_KEY_DO_NOT_EXPOSE"
    mock_status.return_value = {"configured": True, "available": True}
    mock_lookup.return_value = {
        "status": "completed", "duration": 1.0, "error_output": None,
        "hosts": [],
    }

    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id)
    response = client.post(f"/api/assessments/{a_id}/recon/shodan", json={"target_id": t_id})
    assert test_key not in response.text

    history_res = client.get(f"/api/assessments/{a_id}/recon/shodan")
    assert test_key not in history_res.text

    with patch("app.api.routes.recon.check_shodan_status",
               return_value={"configured": True, "available": True}):
        status_res = client.get("/api/recon/shodan/status")
    assert test_key not in status_res.text
    # Status endpoint must only return configured and available
    keys = set(status_res.json().keys())
    assert "api_key" not in keys
    assert keys == {"configured", "available"}


# ============================================================
# Additional: resolve_target_to_ips unit tests
# ============================================================

def test_resolve_ip_address_target():
    """IP Address targets are returned directly without DNS lookup."""
    ips, err = resolve_target_to_ips("IP Address", "1.2.3.4")
    assert err is None
    assert ips == ["1.2.3.4"]


def test_resolve_domain_target_failure():
    """An unresolvable domain returns a helpful error message."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        ips, err = resolve_target_to_ips("Domain", "nonexistent.invalid")
    assert ips == []
    assert err is not None
    assert "nonexistent.invalid" in err


def test_resolve_unsupported_target_type():
    """URL target type is rejected with a clear error."""
    ips, err = resolve_target_to_ips("URL", "https://example.com")
    assert ips == []
    assert "Unsupported target type" in err


def test_assessment_not_found(client):
    """Request with non-existent assessment_id returns 404."""
    fake_id = str(uuid.uuid4())
    response = client.post(
        f"/api/assessments/{fake_id}/recon/shodan",
        json={"target_id": str(uuid.uuid4())}
    )
    assert response.status_code == 404
    assert "Assessment not found" in response.json()["detail"]


def test_target_not_found(client):
    """Request with non-existent target_id returns 404."""
    a_id = _create_assessment(client)
    fake_target_id = str(uuid.uuid4())
    response = client.post(
        f"/api/assessments/{a_id}/recon/shodan",
        json={"target_id": fake_target_id}
    )
    assert response.status_code == 404
    assert "Target not found" in response.json()["detail"]


def test_shodan_rejects_url_target_type(client):
    """URL type targets are not supported for Shodan lookups."""
    a_id = _create_assessment(client)
    t_id = _create_target(client, a_id, target_type="URL", target_value="https://example.com")

    with patch("app.api.routes.recon.check_shodan_status",
               return_value={"configured": True, "available": True}):
        response = client.post(
            f"/api/assessments/{a_id}/recon/shodan",
            json={"target_id": t_id}
        )
    assert response.status_code == 400
    assert "IP Address or Domain" in response.json()["detail"]
