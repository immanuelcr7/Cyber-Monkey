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
from app.services.nuclei_service import check_nuclei_availability, execute_nuclei_scan
from app.models.vulnerability import NucleiScan, NucleiFinding
from app.models.assessment import Assessment
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


# 1. Availability Detection Tests
@patch("subprocess.run")
def test_check_nuclei_availability_installed(mock_run):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "[INF] Nuclei Engine Version: v3.11.1\n"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    installed, version = check_nuclei_availability()
    assert installed is True
    assert version == "v3.11.1"
    mock_run.assert_called_once_with(
        ["nuclei", "-version"],
        capture_output=True,
        text=True,
        timeout=10,
        shell=False
    )

@patch("subprocess.run", side_effect=FileNotFoundError)
def test_check_nuclei_availability_not_found(mock_run):
    installed, version = check_nuclei_availability()
    assert installed is False
    assert version is None


# 2. Execution & JSONL Parsing Tests
@patch("subprocess.run")
def test_execute_nuclei_scan_success(mock_run):
    sample_jsonl = (
        '{"template-id":"ssl-issuer","info":{"name":"SSL Certificate Issuer","severity":"info"},"type":"ssl","host":"example.com:443","matched-at":"https://example.com"}\n'
        '{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"Apache Log4j RCE","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},"type":"http","host":"example.com","matched-at":"http://example.com/login"}\n'
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = sample_jsonl
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    res = execute_nuclei_scan("https://example.com", profile="BASIC")
    assert res["status"] == "completed"
    assert res["finding_count"] == 2
    assert res["findings"][0]["template_id"] == "ssl-issuer"
    assert res["findings"][1]["severity"] == "critical"
    assert res["findings"][1]["cves"] == ["CVE-2021-44228"]
    assert res["findings"][1]["cvss_score"] == 10.0

@patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=300))
def test_execute_nuclei_scan_timeout(mock_run):
    res = execute_nuclei_scan("https://example.com")
    assert res["status"] == "failed"
    assert "timed out" in res["error_output"]

@patch("subprocess.run", side_effect=FileNotFoundError)
def test_execute_nuclei_scan_file_not_found(mock_run):
    res = execute_nuclei_scan("https://example.com")
    assert res["status"] == "failed"
    assert "not found" in res["error_output"]


# 3. API Route Integration Tests
@patch("app.api.routes.vulnerability.check_nuclei_availability", return_value=(True, "v3.11.1"))
def test_get_nuclei_status_api(mock_avail, client):
    res = client.get("/api/vulnerabilities/nuclei/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["version"] == "v3.11.1"

@patch("app.api.routes.vulnerability.check_nuclei_availability", return_value=(True, "v3.11.1"))
@patch("app.api.routes.vulnerability.execute_nuclei_scan")
def test_run_nuclei_scan_authorized(mock_exec, mock_avail, client, db):
    # Setup test assessment and authorized target
    assessment = Assessment(name="Test Assessment", assessment_type="Web Application", status="active")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    target = Target(
        assessment_id=assessment.id,
        target_type="URL",
        target_value="https://example.com",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    mock_exec.return_value = {
        "status": "completed",
        "duration": 5.2,
        "finding_count": 1,
        "error_output": None,
        "findings": [{
            "template_id": "test-template",
            "name": "Test Vulnerability",
            "severity": "medium",
            "type": "http",
            "host": "example.com",
            "matched_at": "https://example.com",
            "description": "Test description",
            "references": ["https://example.com/ref"],
            "cves": ["CVE-2026-0001"],
            "cvss_score": 6.5,
            "raw_result": {}
        }]
    }

    res = client.post(
        f"/api/assessments/{assessment.id}/vulnerabilities/nuclei",
        json={"target_id": str(target.id), "profile": "BASIC"}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "completed"
    assert data["finding_count"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["name"] == "Test Vulnerability"


@patch("app.api.routes.vulnerability.check_nuclei_availability", return_value=(True, "v3.11.1"))
def test_run_nuclei_scan_unauthorized_target_rejected(mock_avail, client, db):
    assessment = Assessment(name="Test Assessment", assessment_type="Web Application", status="active")
    db.add(assessment)
    db.commit()

    # Target not authorized
    target = Target(
        assessment_id=assessment.id,
        target_type="URL",
        target_value="https://unauthorized.com",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(target)
    db.commit()

    res = client.post(
        f"/api/assessments/{assessment.id}/vulnerabilities/nuclei",
        json={"target_id": str(target.id), "profile": "BASIC"}
    )
    assert res.status_code == 400
    assert "not authorized" in res.json()["detail"]
