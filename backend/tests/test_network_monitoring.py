import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_network_telemetry_status():
    resp = client.get("/api/network-monitoring/telemetry/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "zeek" in data
    assert "suricata" in data
    assert data["zeek"]["status"] in ["connected", "not_configured"]

import uuid

def test_network_asset_lifecycle():
    unique_ip = f"10.250.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250 + 1}"
    # 1. Create asset
    resp = client.post("/api/network-monitoring/assets", json={
        "ip_address": unique_ip,
        "hostname": "core-switch-01",
        "asset_type": "switch",
        "monitored": True,
        "ports": [22, 80]
    })
    assert resp.status_code == 201
    asset = resp.json()
    assert asset["ip_address"] == unique_ip
    asset_id = asset["id"]
    assert len(asset["services"]) == 2

    # 2. Add an additional service
    svc_resp = client.post(f"/api/network-monitoring/assets/{asset_id}/services", json={
        "port": 443,
        "protocol": "TCP",
        "service_name": "https"
    })
    assert svc_resp.status_code == 201
    assert svc_resp.json()["port"] == 443

    # 3. Probe asset availability (mock probe to be fast and deterministic)
    with patch("app.api.routes.network_monitoring.probe_port", return_value=(True, 4.25, "OpenSSH 8.9")):
        check_resp = client.post(f"/api/network-monitoring/assets/{asset_id}/check")
        assert check_resp.status_code == 200
        check_data = check_resp.json()
        assert check_data["status"] == "up"
        assert check_data["response_time_ms"] == 4.25

    # 4. Get health summary
    summary_resp = client.get("/api/network-monitoring/health-summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["total_assets"] >= 1
    assert summary["up_assets"] >= 1

    # 5. Authorization check on Nmap discovery
    nmap_resp = client.post("/api/network-monitoring/discover-nmap?target_value=127.0.0.1&authorization_confirmed=false")
    assert nmap_resp.status_code == 400
