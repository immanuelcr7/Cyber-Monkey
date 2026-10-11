import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ai_status():
    resp = client.get("/api/ai/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "configured" in data
    assert "message" in data

def test_ai_analyze_soc():
    payload = {
        "workspace": "soc",
        "task_type": "explain",
        "evidence": {
            "rule_description": "Excessive SSH login failures from unknown host",
            "rule_level": 8,
            "source": "Wazuh",
            "host_name": "srv-db-01",
            "severity": "high"
        }
    }
    resp = client.post("/api/ai/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["workspace"] == "soc"
    assert "SSH" in data["summary"]
    assert len(data["inferences"]) > 0
    assert len(data["recommendations"]) > 0
    assert any("Brute Force" in t for t in data.get("mitre_techniques", []))

def test_ai_analyze_malware():
    payload = {
        "workspace": "malware",
        "task_type": "triage",
        "evidence": {
            "sample_name": "trojan_stealer.exe",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "entropy": 7.82,
            "entropy_assessment": "Packed/Encrypted",
            "is_pe": True,
            "indicators": [
                {"ioc_type": "suspicious_api", "value": "VirtualAlloc"},
                {"ioc_type": "ipv4", "value": "198.51.100.4"}
            ]
        }
    }
    resp = client.post("/api/ai/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["workspace"] == "malware"
    assert "7.82" in data["summary"]
    assert any("packed" in inf.lower() or "packing" in inf.lower() for inf in data["inferences"])

def test_ai_analyze_forensics():
    payload = {
        "workspace": "forensics",
        "task_type": "summarize",
        "evidence": {
            "case_number": "DFIR-2026-004",
            "investigator": "Analyst Dana",
            "evidence_count": 3,
            "timeline_events_count": 12
        }
    }
    resp = client.post("/api/ai/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["workspace"] == "forensics"
    assert "DFIR-2026-004" in data["summary"]

def test_ai_empty_evidence_fails():
    resp = client.post("/api/ai/analyze", json={
        "workspace": "soc",
        "task_type": "explain",
        "evidence": {}
    })
    assert resp.status_code == 400
