import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
import subprocess
import uuid
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.subfinder_service import check_subfinder_availability, execute_subfinder_scan
from app.models.recon import SubfinderScan, Subdomain
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

# 1. Subfinder availability check tests
@patch("subprocess.run")
def test_check_subfinder_availability_installed(mock_run):
    mock_proc = MagicMock()
    mock_proc.stdout = "subfinder version v2.6.6"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    installed, version = check_subfinder_availability()
    assert installed is True
    assert "version v2.6.6" in version
    mock_run.assert_called_once_with(["subfinder", "-version"], capture_output=True, text=True, check=True)

@patch("subprocess.run")
def test_check_subfinder_availability_not_installed(mock_run):
    mock_run.side_effect = FileNotFoundError()
    
    installed, version = check_subfinder_availability()
    assert installed is False
    assert version is None

# 2. Subfinder scan execution tests
@patch("subprocess.run")
@patch("app.services.subfinder_service.check_subfinder_availability")
def test_execute_subfinder_scan_success(mock_check, mock_run):
    mock_check.return_value = (True, "subfinder version v2.6.6")
    
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    # Output includes duplicates and empty lines
    mock_proc.stdout = "api.example.com\napi.example.com\n\nmail.example.com\n"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    result = execute_subfinder_scan("example.com")
    assert result["status"] == "completed"
    assert result["subdomains"] == ["api.example.com", "mail.example.com"]
    assert result["raw_output"] == mock_proc.stdout
    assert result["error_output"] == ""
    assert result["duration"] >= 0

@patch("subprocess.run")
@patch("app.services.subfinder_service.check_subfinder_availability")
def test_execute_subfinder_scan_timeout(mock_check, mock_run):
    mock_check.return_value = (True, "subfinder version v2.6.6")
    timeout_ex = subprocess.TimeoutExpired(cmd=["subfinder"], timeout=180, output="api.example.com")
    timeout_ex.stdout = "api.example.com"
    mock_run.side_effect = timeout_ex
    
    result = execute_subfinder_scan("example.com")
    assert result["status"] == "failed"
    assert "timed out after 180 seconds" in result["error_output"]
    assert result["raw_output"] == "api.example.com"

@patch("subprocess.run")
@patch("app.services.subfinder_service.check_subfinder_availability")
def test_execute_subfinder_scan_failed(mock_check, mock_run):
    mock_check.return_value = (True, "subfinder version v2.6.6")
    
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "Internal Subfinder config error"
    mock_run.return_value = mock_proc
    
    result = execute_subfinder_scan("example.com")
    assert result["status"] == "failed"
    assert "exited with code 1" in result["error_output"]
    assert "Internal Subfinder config error" in result["error_output"]

# 3. Router integration tests (API endpoints)
def test_get_subfinder_status_endpoint(client):
    with patch("app.api.routes.recon.check_sub_availability") as mock_check:
        mock_check.return_value = (True, "subfinder version v2.6.6")
        response = client.get("/api/recon/subfinder/status")
        assert response.status_code == 200
        data = response.json()
        assert data["installed"] is True
        assert data["version"] == "subfinder version v2.6.6"

# 4. Target rejection tests
def test_scan_reject_ip_target(client, db):
    # Create assessment
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Create IP target
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="192.168.1.1",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    # Try calling Subfinder scan
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "only applicable to Domain targets" in scan_res.json()["detail"]

def test_scan_reject_url_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Create URL target
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="URL",
        target_value="https://example.com/login",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    
    # Try calling Subfinder scan
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "only applicable to Domain targets" in scan_res.json()["detail"]

def test_scan_reject_out_of_scope_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Create out of scope domain target
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
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "out of scope" in scan_res.json()["detail"]

def test_scan_reject_unauthorized_target(client, db):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Create unauthorized domain target
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
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": str(t.id)}
    )
    assert scan_res.status_code == 400
    assert "not authorized for scanning" in scan_res.json()["detail"]

def test_scan_reject_target_belonging_to_another_assessment(client):
    # Assessment A
    a_res = client.post("/api/assessments/", json={"name": "A_Alpha", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    # Assessment B
    b_res = client.post("/api/assessments/", json={"name": "A_Beta", "assessment_type": "Cloud"})
    b_id = b_res.json()["id"]
    
    # Create domain target in A
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
    
    # Attempt to scan Target A using Assessment B context
    scan_res = client.post(
        f"/api/assessments/{b_id}/recon/subfinder",
        json={"target_id": t_id}
    )
    assert scan_res.status_code == 400
    assert "does not belong to the requested assessment" in scan_res.json()["detail"]

def test_scan_invalid_target_id(client):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": str(uuid.uuid4())}
    )
    assert scan_res.status_code == 404
    assert "Target not found" in scan_res.json()["detail"]

def test_scan_invalid_missing_target_id_payload(client):
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Web Application"})
    a_id = a_res.json()["id"]
    
    # Missing target_id
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/subfinder",
        json={}
    )
    assert scan_res.status_code == 422

# 5. Success execution and storage checks
@patch("app.api.routes.recon.execute_subfinder_scan")
@patch("app.api.routes.recon.check_sub_availability")
def test_scan_subfinder_successful_and_stored(mock_check, mock_execute, client):
    mock_check.return_value = (True, "subfinder version v2.6.6")
    mock_execute.return_value = {
        "status": "completed",
        "raw_output": "api.example.com\nmail.example.com",
        "error_output": "",
        "duration": 5.2,
        "subdomains": ["api.example.com", "mail.example.com"]
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
        f"/api/assessments/{a_id}/recon/subfinder",
        json={"target_id": t_id}
    )
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "completed"
    assert data["duration"] == 5.2
    assert "api.example.com" in data["raw_output"]
    assert len(data["subdomains"]) == 2
    assert data["subdomains"][0]["subdomain"] == "api.example.com"
    assert data["subdomains"][1]["subdomain"] == "mail.example.com"

    # Fetch scan history and check if it's there
    history_res = client.get(f"/api/assessments/{a_id}/recon/subfinder")
    assert history_res.status_code == 200
    h_data = history_res.json()
    assert len(h_data) == 1
    assert h_data[0]["id"] == data["id"]
    assert h_data[0]["target"]["target_value"] == "example.com"
    assert len(h_data[0]["subdomains"]) == 2

# 6. Subfinder profile/command safety: no shell=True
@patch("subprocess.run")
@patch("app.services.subfinder_service.check_subfinder_availability")
def test_subfinder_command_safety_no_shell(mock_check, mock_run):
    mock_check.return_value = (True, "subfinder version v2.6.6")
    
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "api.example.com"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    execute_subfinder_scan("example.com; rm -rf /")
    
    # Verify subprocess arguments
    called_args = mock_run.call_args[0][0]
    assert called_args[0] == "subfinder"
    assert "-d" in called_args
    assert "example.com; rm -rf /" in called_args
    
    # Verify shell=True is NOT passed (defaults to None/False)
    called_kwargs = mock_run.call_args[1]
    assert called_kwargs.get("shell") is not True
