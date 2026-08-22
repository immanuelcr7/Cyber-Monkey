import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
import subprocess
from uuid import uuid4
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.nmap_service import check_nmap_availability, execute_nmap_scan
from app.models.recon import NmapScan, NmapPort

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

# 1. Nmap availability check tests
@patch("subprocess.run")
def test_check_nmap_availability_installed(mock_run):
    mock_proc = MagicMock()
    mock_proc.stdout = "Nmap version 7.92 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu"
    mock_run.return_value = mock_proc
    
    installed, version = check_nmap_availability()
    assert installed is True
    assert "Nmap version 7.92" in version
    mock_run.assert_called_once_with(["nmap", "--version"], capture_output=True, text=True, check=True)

@patch("subprocess.run")
def test_check_nmap_availability_not_installed(mock_run):
    mock_run.side_effect = FileNotFoundError()
    
    installed, version = check_nmap_availability()
    assert installed is False
    assert version is None


# 2. Nmap service execution logic, predefined arguments, timeout, no shell=True
@patch("subprocess.run")
@patch("app.services.nmap_service.check_nmap_availability")
def test_execute_nmap_scan_host_discovery(mock_check, mock_run):
    mock_check.return_value = (True, "Nmap version 7.92")
    
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "<nmaprun></nmaprun>"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc
    
    # We patch parse_nmap_xml to avoid reading non-existent temp file
    with patch("app.services.nmap_service.parse_nmap_xml") as mock_parse:
        mock_parse.return_value = []
        result = execute_nmap_scan("127.0.0.1", "host_discovery")
        
        assert result["status"] == "completed"
        assert result["ports"] == []
        
        # Verify subprocess arguments
        called_args = mock_run.call_args[0][0]
        assert called_args[0] == "nmap"
        assert "-sn" in called_args
        assert "127.0.0.1" in called_args
        
        # Verify security: no shell=True
        called_kwargs = mock_run.call_args[1]
        assert called_kwargs.get("shell") is not True
        assert called_kwargs.get("timeout") == 180

@patch("subprocess.run")
@patch("app.services.nmap_service.check_nmap_availability")
def test_execute_nmap_scan_comprehensive_timeout(mock_check, mock_run):
    mock_check.return_value = (True, "Nmap version 7.92")
    timeout_ex = subprocess.TimeoutExpired(cmd=["nmap"], timeout=360, output="partial stdout")
    timeout_ex.stdout = "partial stdout"
    mock_run.side_effect = timeout_ex
    
    result = execute_nmap_scan("127.0.0.1", "comprehensive")
    
    assert result["status"] == "failed"
    assert "timed out after 360 seconds" in result["error_output"]
    assert result["raw_output"] == "partial stdout"


# 3. Router integration tests (API endpoints)
def test_get_nmap_status_endpoint(client):
    with patch("app.api.routes.recon.check_nmap_availability") as mock_check:
        mock_check.return_value = (True, "Nmap version 7.92")
        response = client.get("/api/recon/nmap/status")
        assert response.status_code == 200
        data = response.json()
        assert data["installed"] is True
        assert data["version"] == "Nmap version 7.92"

def test_scan_unauthorized_target(client, db):
    import uuid
    from app.models.target import Target
    # Create assessment
    a_res = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    # Create target (not authorized) via DB to bypass POST route validator
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="192.168.1.1",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    
    # Post scan request
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/nmap",
        json={"target_id": str(t.id), "scan_profile": "basic_port"}
    )
    assert scan_res.status_code == 400
    assert "not authorized for scanning" in scan_res.json()["detail"]

def test_scan_out_of_scope_target(client, db):
    import uuid
    from app.models.target import Target
    a_res = client.post("/api/assessments/", json={"name": "A2", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    # Bypass frontend confirmation constraint by writing direct out_of_scope target via DB
    t = Target(
        assessment_id=uuid.UUID(a_id),
        target_type="IP Address",
        target_value="192.168.1.2",
        scope_status="out_of_scope",
        authorization_confirmed=True
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/nmap",
        json={"target_id": str(t.id), "scan_profile": "basic_port"}
    )
    assert scan_res.status_code == 400
    assert "out of scope" in scan_res.json()["detail"]

def test_scan_target_belonging_to_another_assessment(client):
    # Assessment A
    a_res = client.post("/api/assessments/", json={"name": "A_Alpha", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    # Assessment B
    b_res = client.post("/api/assessments/", json={"name": "A_Beta", "assessment_type": "Cloud"})
    b_id = b_res.json()["id"]
    
    # Create target in A
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "192.168.1.3",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    # Attempt to scan Target A using Assessment B context
    scan_res = client.post(
        f"/api/assessments/{b_id}/recon/nmap",
        json={"target_id": t_id, "scan_profile": "basic_port"}
    )
    assert scan_res.status_code == 400
    assert "does not belong to the requested assessment" in scan_res.json()["detail"]

def test_scan_invalid_scan_profile(client):
    a_res = client.post("/api/assessments/", json={"name": "A3", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "192.168.1.4",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/nmap",
        json={"target_id": t_id, "scan_profile": "destructive_exploit"}
    )
    assert scan_res.status_code == 400
    assert "Invalid scan profile" in scan_res.json()["detail"]

def test_scan_nmap_not_installed_error(client):
    a_res = client.post("/api/assessments/", json={"name": "A4", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "192.168.1.5",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    with patch("app.api.routes.recon.check_nmap_availability") as mock_check:
        mock_check.return_value = (False, None)
        scan_res = client.post(
            f"/api/assessments/{a_id}/recon/nmap",
            json={"target_id": t_id, "scan_profile": "basic_port"}
        )
        assert scan_res.status_code == 503
        assert "Nmap is not installed on the backend" in scan_res.json()["detail"]

@patch("app.api.routes.recon.execute_nmap_scan")
@patch("app.api.routes.recon.check_nmap_availability")
def test_scan_nmap_successful_and_stored(mock_check, mock_execute, client):
    mock_check.return_value = (True, "Nmap version 7.92")
    mock_execute.return_value = {
        "status": "completed",
        "raw_output": "Nmap scan report for localhost (127.0.0.1)\nPORT STATE SERVICE\n80/tcp open http",
        "error_output": "",
        "duration": 4.5,
        "ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache HTTPD 2.4.41"}
        ]
    }
    
    a_res = client.post("/api/assessments/", json={"name": "A5", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "127.0.0.1",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/nmap",
        json={"target_id": t_id, "scan_profile": "service_detection"}
    )
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "completed"
    assert data["duration"] == 4.5
    assert "80/tcp open http" in data["raw_output"]
    assert len(data["ports"]) == 1
    assert data["ports"][0]["port"] == 80
    assert data["ports"][0]["service"] == "http"
    assert data["ports"][0]["version"] == "Apache HTTPD 2.4.41"

    # Fetch scan history and check if it's there
    history_res = client.get(f"/api/assessments/{a_id}/recon/nmap")
    assert history_res.status_code == 200
    h_data = history_res.json()
    assert len(h_data) == 1
    assert h_data[0]["id"] == data["id"]
    assert h_data[0]["target"]["target_value"] == "127.0.0.1"

@patch("app.api.routes.recon.execute_nmap_scan")
@patch("app.api.routes.recon.check_nmap_availability")
def test_scan_nmap_failed_and_stored(mock_check, mock_execute, client):
    mock_check.return_value = (True, "Nmap version 7.92")
    mock_execute.return_value = {
        "status": "failed",
        "raw_output": "",
        "error_output": "Nmap execution exited with code 2",
        "duration": 1.2,
        "ports": []
    }
    
    a_res = client.post("/api/assessments/", json={"name": "A6", "assessment_type": "Cloud"})
    a_id = a_res.json()["id"]
    
    t_res = client.post(
        f"/api/assessments/{a_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "127.0.0.1",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    t_id = t_res.json()["id"]
    
    scan_res = client.post(
        f"/api/assessments/{a_id}/recon/nmap",
        json={"target_id": t_id, "scan_profile": "basic_port"}
    )
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["status"] == "failed"
    assert "exited with code 2" in data["error_output"]
    assert len(data["ports"]) == 0
