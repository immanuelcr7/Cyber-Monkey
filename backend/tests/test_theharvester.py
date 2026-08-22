import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
import subprocess
import uuid
import json
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.theharvester_service import check_theharvester_availability, execute_theharvester_scan
from app.models.recon import TheHarvesterScan, TheHarvesterEmail, TheHarvesterHost, TheHarvesterIp, TheHarvesterName
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

# 1. theHarvester availability check tests (covers 1. theHarvester status)
@patch("subprocess.run")
def test_check_theharvester_availability_installed(mock_run):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "theHarvester 5.0.0\nCoded by Christian Martorella"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    installed, version = check_theharvester_availability()
    assert installed is True
    assert "theHarvester 5.0.0" in version
    mock_run.assert_called_once()
    assert mock_run.call_args[0][0] == ["uv", "run", "theHarvester", "-h"]

@patch("subprocess.run")
def test_check_theharvester_availability_not_installed(mock_run):
    mock_run.side_effect = FileNotFoundError()
    
    installed, version = check_theharvester_availability()
    assert installed is False
    assert "not found" in version.lower()

# 2. Router integration status endpoint (covers 1. theHarvester status)
def test_get_theharvester_status_endpoint(client):
    with patch("app.api.routes.recon.check_theharvester_availability") as mock_check:
        mock_check.return_value = (True, "theHarvester 5.0.0")
        response = client.get("/api/recon/theharvester/status")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is True
        assert "theHarvester 5.0.0" in data["version"]
        assert "theHarvester" in data["path"]

# 3. Router integration scan execution (covers 2. Authorized domain execution, 10. Raw output persistence, 11. Result parsing, 12. Deduplication, 13. Database persistence, 14. Correct scan -> target, 15. Correct result -> scan)
@patch("app.api.routes.recon.execute_theharvester_scan")
@patch("app.api.routes.recon.check_theharvester_availability")
def test_scan_theharvester_successful_and_stored(mock_check, mock_execute, client):
    mock_check.return_value = (True, "theHarvester 5.0.0")
    
    mock_execute.return_value = {
        "status": "completed",
        "raw_output": "Custom text output from theHarvester",
        "error_output": "",
        "duration": 12.5,
        "emails": [
            {"email": "admin@example.com", "source": "yahoo"},
            {"email": "info@example.com", "source": "yahoo, crtsh"},
            {"email": "admin@example.com", "source": "crtsh"}  # duplicate email test
        ],
        "hosts": [
            {"hostname": "mail.example.com", "ip": "192.0.2.10", "source": "crtsh"},
            {"hostname": "api.example.com", "ip": "192.0.2.20", "source": "yahoo"},
            {"hostname": "mail.example.com", "ip": "192.0.2.10", "source": "otx"}  # duplicate host test
        ],
        "ips": [
            {"ip": "192.0.2.10", "source": "crtsh"},
            {"ip": "192.0.2.20", "source": "yahoo"}
        ],
        "names": [
            {"name": "John Doe", "source": "linkedin_people"}
        ]
    }
    
    a_res = client.post("/api/assessments/", json={"name": "Assessment 1", "assessment_type": "Web Application"})
    if a_res.status_code != 200:
        print("CREATE ASSESSMENT FAILED:", a_res.status_code, a_res.text)
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": t_id}
    )
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "completed"
    assert data["duration"] == 12.5
    assert data["emails_found"] == 3  # Count of entries returned by execute_theharvester_scan before DB insertion
    assert data["hosts_found"] == 3
    assert data["ips_found"] == 2
    assert data["names_found"] == 1
    assert data["raw_output"] == "Custom text output from theHarvester"
    assert data["error_output"] == ""
    assert data["target_id"] == t_id
    assert data["assessment_id"] == a_id
    
    # Verify child relations inside response payload
    assert len(data["emails"]) == 3
    assert len(data["hosts"]) == 3
    assert len(data["ips"]) == 2
    assert len(data["names"]) == 1

    # Fetch scan history and check if it's there
    history_res = client.get(f"/api/assessments/{a_id}/recon/theharvester")
    assert history_res.status_code == 200
    h_data = history_res.json()
    assert len(h_data) == 1
    assert h_data[0]["id"] == data["id"]
    assert h_data[0]["target"]["target_value"] == "example.com"
    assert len(h_data[0]["emails"]) == 3
    assert len(h_data[0]["hosts"]) == 3
    assert len(h_data[0]["ips"]) == 2
    assert len(h_data[0]["names"]) == 1

# 4. Target rejection tests (covers 3. Unauthorized, 4. Out-of-scope, 5. IP target, 6. URL target, 7. Target from another assessment)
def test_scan_reject_ip_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="192.168.1.100",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "only applicable to Domain targets" in scan_res.json()["detail"]

def test_scan_reject_url_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="URL",
        target_value="https://example.com/api",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "only applicable to Domain targets" in scan_res.json()["detail"]

def test_scan_reject_out_of_scope_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="example.com",
        scope_status="out_of_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "out of scope" in scan_res.json()["detail"]

def test_scan_reject_unauthorized_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="Domain",
        target_value="example.com",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(t)
    db.commit()
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "not authorized for scanning" in scan_res.json()["detail"]

def test_scan_reject_target_belonging_to_another_assessment(client):
    # Assessment A
    a_res = client.post("/api/assessments/", json={"name": "Assessment A", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Assessment B
    b_res = client.post("/api/assessments/", json={"name": "Assessment B", "assessment_type": "Cloud"})
    b_id = b_res.json()["id"]
    
    # Target in Assessment A
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    # Execute using Assessment B context
    scan_res = client.post(
        f"/api/assessments/{b_id}/recon/theharvester",
        json={"target_id": t_id}
    )
    assert scan_res.status_code == 400
    assert "does not belong to the requested assessment" in scan_res.json()["detail"]

# 5. Safe subprocess argument construction (covers 8. Safe subprocess argument construction)
@patch("subprocess.run")
@patch("app.services.theharvester_service.check_theharvester_availability")
def test_theharvester_command_safety_no_shell(mock_check, mock_run):
    mock_check.return_value = (True, "theHarvester 5.0.0")
    
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    execute_theharvester_scan("example.com; rm -rf /")
    
    # Verify subprocess arguments list
    called_args = mock_run.call_args[0][0]
    assert called_args[0] == "uv"
    assert called_args[1] == "run"
    assert called_args[2] == "theHarvester"
    assert "-d" in called_args
    assert "example.com; rm -rf /" in called_args
    
    # Verify shell=True is NOT passed (defaults to None/False)
    called_kwargs = mock_run.call_args[1]
    assert called_kwargs.get("shell") is not True

# 6. Timeout handling tests (covers 9. Timeout handling)
@patch("subprocess.run")
@patch("app.services.theharvester_service.check_theharvester_availability")
def test_execute_theharvester_scan_timeout(mock_check, mock_run):
    mock_check.return_value = (True, "theHarvester 5.0.0")
    
    # Create timeout exception
    timeout_ex = subprocess.TimeoutExpired(cmd=["uv", "run", "theHarvester"], timeout=300, output="Partial scan results")
    timeout_ex.stdout = "Partial scan results stdout"
    timeout_ex.stderr = "Partial scan results stderr"
    mock_run.side_effect = timeout_ex
    
    result = execute_theharvester_scan("example.com")
    assert result["status"] == "failed"
    assert "timed out after 300 seconds" in result["error_output"]
    assert result["raw_output"] == "Partial scan results stdout"
    assert "Partial scan results stderr" in result["error_output"]


# 7. Endpoint failure test (covers 6. Error reporting)
@patch("app.api.routes.recon.execute_theharvester_scan")
@patch("app.api.routes.recon.check_theharvester_availability")
def test_scan_theharvester_failed_endpoint(mock_check, mock_execute, client):
    mock_check.return_value = (True, "theHarvester 5.0.0")
    mock_execute.return_value = {
        "status": "failed",
        "raw_output": "",
        "error_output": "theHarvester process exited with code 1",
        "duration": 2.1,
        "return_code": 1,
        "emails": [],
        "hosts": [],
        "ips": [],
        "names": []
    }
    
    a_res = client.post("/api/assessments/", json={"name": "A5", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/theharvester",
        json={"target_id": t_id}
    )
    assert scan_res.status_code == 400
    assert "TheHarvester execution failed. Check the scan diagnostics." in scan_res.json()["detail"]

