import os
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

@patch("app.api.routes.standalone.check_nmap_availability", return_value=(True, "v7.92"))
@patch("app.api.routes.standalone.execute_nmap_scan")
def test_run_standalone_nmap_success(mock_exec, mock_avail):
    mock_exec.return_value = {
        "status": "completed",
        "scan_profile": "service_detection",
        "target": "127.0.0.1",
        "host_status": "up",
        "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
    }

    res = client.post(
        "/api/standalone/recon/nmap",
        json={
            "target_value": "127.0.0.1",
            "scan_profile": "service_detection",
            "authorization_confirmed": True
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["target"] == "127.0.0.1"
    assert len(data["ports"]) == 1
    mock_exec.assert_called_once_with(target_val="127.0.0.1", scan_profile="service_detection")


def test_run_standalone_nmap_unauthorized_rejected():
    res = client.post(
        "/api/standalone/recon/nmap",
        json={
            "target_value": "127.0.0.1",
            "scan_profile": "service_detection",
            "authorization_confirmed": False
        }
    )
    assert res.status_code == 400
    assert "authorization must be explicitly confirmed" in res.json()["detail"]


@patch("app.api.routes.standalone.check_nikto_availability", return_value=(True, "v2.6.1"))
@patch("app.api.routes.standalone.execute_nikto_scan")
def test_run_standalone_nikto_success(mock_exec, mock_avail):
    mock_exec.return_value = {
        "status": "completed",
        "duration": 3.5,
        "finding_count": 1,
        "summary": {"total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "findings": [{"title": "Test finding", "severity": "medium"}],
        "target": "192.168.1.35",
        "port": 8000
    }

    res = client.post(
        "/api/standalone/vulnerabilities/nikto",
        json={
            "target_value": "192.168.1.35",
            "port": 8000,
            "authorization_confirmed": True
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["target"] == "192.168.1.35"
    assert data["port"] == 8000
    mock_exec.assert_called_once_with(target_val="192.168.1.35", port=8000)


def test_run_standalone_nikto_invalid_port_rejected():
    res = client.post(
        "/api/standalone/vulnerabilities/nikto",
        json={
            "target_value": "192.168.1.35",
            "port": 70000,
            "authorization_confirmed": True
        }
    )
    assert res.status_code == 400
    assert "Invalid port" in res.json()["detail"]


@patch("app.api.routes.standalone.check_nuclei_availability", return_value=(True, "v3.11.1"))
@patch("app.api.routes.standalone.execute_nuclei_scan")
def test_run_standalone_nuclei_success(mock_exec, mock_avail):
    mock_exec.return_value = {
        "status": "completed",
        "duration": 2.1,
        "finding_count": 0,
        "findings": []
    }

    res = client.post(
        "/api/standalone/vulnerabilities/nuclei",
        json={
            "target_value": "https://example.com",
            "profile": "BASIC",
            "authorization_confirmed": True
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "completed"


@patch("app.api.routes.standalone.check_subfinder_availability", return_value=(True, "v2.6.0"))
@patch("app.api.routes.standalone.execute_subfinder_scan")
def test_run_standalone_subfinder_success(mock_exec, mock_avail):
    mock_exec.return_value = {
        "status": "completed",
        "domain": "example.com",
        "subdomain_count": 2,
        "subdomains": ["sub1.example.com", "sub2.example.com"]
    }

    res = client.post(
        "/api/standalone/recon/subfinder",
        json={
            "target_value": "example.com",
            "authorization_confirmed": True
        }
    )
    assert res.status_code == 200
    assert res.json()["subdomain_count"] == 2
