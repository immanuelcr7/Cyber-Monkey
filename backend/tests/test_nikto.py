import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
import subprocess
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.nikto_service import (
    check_nikto_availability,
    execute_nikto_scan,
    parse_nikto_output,
    sanitize_target_and_port
)

from app.models.vulnerability import NiktoScan, NiktoFinding
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
@patch("os.path.exists", return_value=True)
@patch("subprocess.run")
def test_check_nikto_availability_installed(mock_run, mock_exists):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "This is perl 5, version 32, subversion 1"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    installed, version = check_nikto_availability()
    assert installed is True
    assert version == "v2.6.1"
    mock_run.assert_called_once_with(
        [r"C:\Strawberry\perl\bin\perl.exe", "-v"],
        capture_output=True,
        text=True,
        timeout=10,
        shell=False
    )

@patch("os.path.exists", return_value=False)
def test_check_nikto_availability_not_found(mock_exists):
    installed, version = check_nikto_availability()
    assert installed is False
    assert version is None


# 2. Execution & Output Parsing Tests
def test_parse_nikto_output():
    sample_stdout = (
        "- Nikto v2.5.0\n"
        "+ Target IP:          127.0.0.1\n"
        "+ Target Hostname:    localhost\n"
        "+ Target Port:        80\n"
        "+ Start Time:         2026-08-31 18:00:00\n"
        "---------------------------------------------------------------------------\n"
        "+ OSVDB-3268: /: Directory indexing found.\n"
        "+ OSVDB-3092: /admin/: Admin login page found with sensitive config.\n"
        "+ The Anti-clickjacking X-Frame-Options header is not present.\n"
        "+ RCE command execution vulnerability detected via parameter input.\n"
        "---------------------------------------------------------------------------\n"
        "+ 1 host(s) tested\n"
    )
    findings, summary = parse_nikto_output(sample_stdout)
    assert len(findings) == 4
    assert summary["total"] == 4
    assert summary["critical"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 2

    assert findings[0]["nikto_id"] == "OSVDB-3268"
    assert findings[0]["endpoint"] == "/"
    assert findings[1]["nikto_id"] == "OSVDB-3092"
    assert findings[1]["endpoint"] == "/admin/"
    assert findings[3]["severity"] == "critical"

@patch("subprocess.run")
def test_execute_nikto_scan_success(mock_run):
    sample_stdout = (
        "+ OSVDB-3268: /: Directory indexing found.\n"
        "+ OSVDB-3092: /admin/: Admin page found.\n"
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = sample_stdout
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    res = execute_nikto_scan("127.0.0.1", port=8080)
    assert res["status"] == "completed"
    assert res["finding_count"] == 2
    assert res["summary"]["total"] == 2
    mock_run.assert_called_once_with(
        [
            r"C:\Strawberry\perl\bin\perl.exe",
            r"C:\Users\dhina\Desktop\Cyber Monkey\nikto\program\nikto.pl",
            "-h",
            "127.0.0.1",
            "-p",
            "8080"
        ],
        capture_output=True,
        text=True,
        timeout=300,
        shell=False
    )

@patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nikto", timeout=300))
def test_execute_nikto_scan_timeout(mock_run):
    res = execute_nikto_scan("127.0.0.1")
    assert res["status"] == "failed"
    assert "timed out" in res["error_output"]

@patch("subprocess.run", side_effect=FileNotFoundError("Perl not found"))
def test_execute_nikto_scan_file_not_found(mock_run):
    res = execute_nikto_scan("127.0.0.1")
    assert res["status"] == "failed"
    assert "not found" in res["error_output"]


# 3. API Route Integration Tests
@patch("app.api.routes.vulnerability.check_nikto_availability", return_value=(True, "v2.6.1"))
def test_get_nikto_status_api(mock_avail, client):
    res = client.get("/api/vulnerabilities/nikto/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["version"] == "v2.6.1"
    assert r"C:\Strawberry\perl\bin\perl.exe" in data["perl_executable"]
    assert r"nikto.pl" in data["nikto_executable"]

@patch("app.api.routes.vulnerability.check_nikto_availability", return_value=(True, "v2.6.1"))
@patch("app.api.routes.vulnerability.execute_nikto_scan")
def test_run_nikto_scan_authorized(mock_exec, mock_avail, client, db):
    assessment = Assessment(name="Test Assessment", assessment_type="Web Application", status="active")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    target = Target(
        assessment_id=assessment.id,
        target_type="IP",
        target_value="127.0.0.1",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    mock_exec.return_value = {
        "status": "completed",
        "duration": 4.1,
        "finding_count": 1,
        "summary": {"total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "error_output": None,
        "findings": [{
            "nikto_id": "OSVDB-3092",
            "title": "/admin/ login page found",
            "description": "/admin/: Admin login page found with sensitive config.",
            "severity": "medium",
            "endpoint": "/admin/",
            "evidence": "OSVDB-3092: /admin/: Admin login page found",
            "remediation": None,
            "raw_line": "+ OSVDB-3092: /admin/: Admin login page found"
        }]
    }

    res = client.post(
        f"/api/assessments/{assessment.id}/vulnerabilities/nikto",
        json={"target_id": str(target.id), "port": 80}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "completed"
    assert data["finding_count"] == 1
    assert data["scanner"] == "nikto"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "/admin/ login page found"
    assert data["findings"][0]["severity"] == "medium"

@patch("app.api.routes.vulnerability.check_nikto_availability", return_value=(True, "v2.6.1"))
def test_run_nikto_scan_unauthorized_target_rejected(mock_avail, client, db):
    assessment = Assessment(name="Test Assessment", assessment_type="Web Application", status="active")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    target = Target(
        assessment_id=assessment.id,
        target_type="IP",
        target_value="192.168.1.1",
        scope_status="in_scope",
        authorization_confirmed=False
    )
    db.add(target)
    db.commit()

    res = client.post(
        f"/api/assessments/{assessment.id}/vulnerabilities/nikto",
        json={"target_id": str(target.id), "port": 80}
    )
    assert res.status_code == 400
    assert "not authorized" in res.json()["detail"]

@patch("app.api.routes.vulnerability.check_nikto_availability", return_value=(True, "v2.6.1"))
def test_get_nikto_scans_api(mock_avail, client, db):
    assessment = Assessment(name="Test Assessment", assessment_type="Web Application", status="active")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    target = Target(
        assessment_id=assessment.id,
        target_type="IP",
        target_value="127.0.0.1",
        scope_status="in_scope",
        authorization_confirmed=True
    )
    db.add(target)
    db.commit()

    scan = NiktoScan(
        assessment_id=assessment.id,
        target_id=target.id,
        target_host=target.target_value,
        port=80,
        status="completed",
        finding_count=0,
        summary={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    db.add(scan)
    db.commit()

    res = client.get(f"/api/assessments/{assessment.id}/vulnerabilities/nikto")
    assert res.status_code == 200
    scans = res.json()
    assert len(scans) == 1
    assert scans[0]["target"] == "127.0.0.1"
    assert scans[0]["scanner"] == "nikto"


# 4. Port Handling & Target Sanitization Unit & Regression Tests

def test_sanitize_target_and_port_unit():
    """
    Unit tests for target sanitization and port validation logic.
    """
    # 1. Clean IP with custom port
    host, p = sanitize_target_and_port("192.168.1.35", 8000)
    assert host == "192.168.1.35"
    assert p == 8000

    # 2. Embedded port in target string, but explicit user port provided -> user port wins
    host, p = sanitize_target_and_port("192.168.1.35:50", 8000)
    assert host == "192.168.1.35"
    assert p == 8000

    # 3. URL scheme with port and path -> clean hostname extracted and port preserved
    host, p = sanitize_target_and_port("http://192.168.1.35:8000/api/health", None)
    assert host == "192.168.1.35"
    assert p == 8000

    # 4. Invalid port range raises ValueError
    with pytest.raises(ValueError, match="out of valid range"):
        sanitize_target_and_port("192.168.1.35", 70000)

    with pytest.raises(ValueError, match="out of valid range"):
        sanitize_target_and_port("192.168.1.35", 0)


@patch("subprocess.run")
def test_nikto_regression_target_192_168_1_35_port_8000(mock_run):
    """
    Requirement 8: Add a regression test specifically for target 192.168.1.35 with port 8000.
    Verifies that execute_nikto_scan passes exact clean host '192.168.1.35' and port '8000'
    to subprocess.run without hardcoded '50' or port truncation.
    """
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "+ Server: uvicorn\n+ OSVDB-0: /: Test response\n"
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    # Execution with clean IP 192.168.1.35 and port 8000
    res = execute_nikto_scan("192.168.1.35", port=8000)
    assert res["status"] == "completed"
    assert res["target"] == "192.168.1.35"
    assert res["port"] == 8000

    mock_run.assert_called_with(
        [
            r"C:\Strawberry\perl\bin\perl.exe",
            r"C:\Users\dhina\Desktop\Cyber Monkey\nikto\program\nikto.pl",
            "-h",
            "192.168.1.35",
            "-p",
            "8000"
        ],
        capture_output=True,
        text=True,
        timeout=300,
        shell=False
    )

    # Execution with dirty IP 192.168.1.35:50 and port 8000 (ensuring :50 is stripped)
    res_dirty = execute_nikto_scan("192.168.1.35:50", port=8000)
    assert res_dirty["status"] == "completed"
    assert res_dirty["target"] == "192.168.1.35"
    assert res_dirty["port"] == 8000

    mock_run.assert_called_with(
        [
            r"C:\Strawberry\perl\bin\perl.exe",
            r"C:\Users\dhina\Desktop\Cyber Monkey\nikto\program\nikto.pl",
            "-h",
            "192.168.1.35",
            "-p",
            "8000"
        ],
        capture_output=True,
        text=True,
        timeout=300,
        shell=False
    )

