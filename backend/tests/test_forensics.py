import io
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_forensics_status():
    resp = client.get("/api/forensics/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "SHA-256" in data["hashing_algorithm"]

def test_forensics_case_lifecycle():
    case_num = f"DFIR-TEST-{datetime.utcnow().strftime('%H%M%S')}"

    # 1. Create Case
    resp = client.post("/api/forensics/cases", json={
        "case_number": case_num,
        "title": "Unauthorized Persistence Investigation",
        "description": "Analysis of suspicious workstation autorun entries",
        "investigator": "Detective Frank",
        "priority": "high"
    })
    assert resp.status_code == 201
    case = resp.json()
    assert case["case_number"] == case_num
    case_id = case["id"]

    # 2. Acquire Evidence file
    evidence_bytes = b"2026-01-10 12:00:00 Registry RunKey added: C:\\Windows\\Temp\\backdoor.exe"
    files = {"file": ("auth_log.txt", io.BytesIO(evidence_bytes), "text/plain")}
    data = {
        "evidence_identifier": "EVD-001",
        "media_type": "log_file",
        "source_location": "Host WS-09 / C:\\Windows\\System32\\winevt",
        "collector_name": "Detective Frank",
        "notes": "Acquired via read-only triage disk acquisition."
    }
    acq_resp = client.post(f"/api/forensics/cases/{case_id}/evidence", files=files, data=data)
    assert acq_resp.status_code == 201
    ev_data = acq_resp.json()
    assert ev_data["evidence_identifier"] == "EVD-001"
    assert ev_data["verification_status"] == "VERIFIED"
    assert len(ev_data["acquisition_sha256"]) == 64
    ev_id = ev_data["id"]

    # 3. Verify integrity on-demand
    verify_resp = client.post(f"/api/forensics/evidence/{ev_id}/verify-integrity")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["matches"] is True
    assert verify_data["status"] == "VERIFIED"

    # 4. Add chain of custody event
    custody_resp = client.post(f"/api/forensics/evidence/{ev_id}/custody", json={
        "action": "CUSTODY_TRANSFER",
        "performed_by": "Detective Frank",
        "location": "Evidence Locker Safe B",
        "reason": "Secure custody transfer into evidence locker."
    })
    assert custody_resp.status_code == 200
    assert custody_resp.json()["action"] == "CUSTODY_TRANSFER"

    # 5. Add timeline event
    tl_resp = client.post(f"/api/forensics/cases/{case_id}/timeline", json={
        "timestamp": datetime.utcnow().isoformat(),
        "event_source": "Registry Autorun",
        "source_host": "WS-09",
        "user_account": "SYSTEM",
        "event_description": "Persistence key created in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "severity": "high",
        "evidence_id": ev_id
    })
    assert tl_resp.status_code == 200
    assert tl_resp.json()["source_host"] == "WS-09"

    # 6. Export case to JSON and CSV
    json_resp = client.get(f"/api/forensics/cases/{case_id}/export/json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]

    csv_resp = client.get(f"/api/forensics/cases/{case_id}/export/timeline-csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "Timestamp,Source,Host" in csv_resp.text
