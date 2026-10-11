import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_soc_status():
    response = client.get("/api/soc/status")
    assert response.status_code == 200
    data = response.json()
    assert "configured" in data
    assert "connected" in data
    assert "message" in data

def test_soc_sync_unconfigured():
    # If not configured, should return 400 with honest error
    response = client.post("/api/soc/wazuh/sync")
    assert response.status_code in [400, 503]

def test_soc_alert_lifecycle():
    # 1. Create/Ingest an alert
    payload = {
        "rule_id": "100201",
        "rule_description": "Multiple SSH failed login attempts detected",
        "rule_level": 8,
        "severity": "high",
        "source": "Wazuh / Auth Log",
        "host_name": "srv-prod-01",
        "host_ip": "10.0.1.25",
        "evidence": "Jan 12 10:14:02 srv-prod-01 sshd[1245]: Failed password for invalid user admin from 198.51.100.2"
    }
    create_resp = client.post("/api/soc/alerts", json=payload)
    assert create_resp.status_code == 201
    alert_data = create_resp.json()
    assert alert_data["rule_id"] == "100201"
    assert alert_data["severity"] == "high"
    assert alert_data["status"] == "new"
    alert_id = alert_data["id"]

    # 2. Get alerts list with filter
    list_resp = client.get("/api/soc/alerts?severity=high")
    assert list_resp.status_code == 200
    alerts = list_resp.json()
    assert any(a["id"] == alert_id for a in alerts)

    # 3. Add note to alert
    note_resp = client.post(f"/api/soc/alerts/{alert_id}/notes", json={
        "author": "Analyst Alice",
        "note": "IP 198.51.100.2 has attempted 45 auth attempts in 3 minutes."
    })
    assert note_resp.status_code == 200
    assert note_resp.json()["note"] == "IP 198.51.100.2 has attempted 45 auth attempts in 3 minutes."

    # 4. Create an incident linking this alert
    inc_resp = client.post("/api/soc/incidents", json={
        "title": "SSH Credential Stuffing on Production Server",
        "description": "Correlated brute-force attack originating from external IP",
        "severity": "high",
        "assigned_to": "Analyst Alice",
        "category": "Unauthorized Access",
        "alert_ids": [alert_id]
    })
    assert inc_resp.status_code == 201
    inc_data = inc_resp.json()
    assert "INC-" in inc_data["incident_number"]
    assert inc_data["status"] == "open"
    inc_id = inc_data["id"]

    # 5. Verify alert status updated
    detail_resp = client.get(f"/api/soc/alerts/{alert_id}")
    assert detail_resp.status_code == 200
    updated_alert = detail_resp.json()
    assert updated_alert["incident_id"] == inc_id

    # 6. Update incident status
    patch_resp = client.patch(f"/api/soc/incidents/{inc_id}", json={
        "status": "contained",
        "description": "Firewall drop rule applied for 198.51.100.2"
    })
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "contained"

    # 7. Check audit logs
    audit_resp = client.get("/api/soc/audit-logs")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) > 0
