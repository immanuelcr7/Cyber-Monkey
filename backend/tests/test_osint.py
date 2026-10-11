import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_osint_tools_status():
    resp = client.get("/api/osint/tools/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "subfinder" in data
    assert "dns" in data
    assert "whois_rdap" in data
    assert "shodan" in data

def test_osint_investigation_authorization_required():
    # Authorization not confirmed must fail
    resp = client.post("/api/osint/investigations", json={
        "title": "Unauthorized Test",
        "target": "example.com",
        "investigation_purpose": "Security assessment without consent",
        "authorization_confirmed": False
    })
    assert resp.status_code == 400

def test_osint_investigation_lifecycle():
    # 1. Create authorized investigation
    resp = client.post("/api/osint/investigations", json={
        "title": "Operation Alpha Recon",
        "target": "example.com",
        "scope_description": "Public domain and mail infrastructure mapping",
        "investigation_purpose": "Authorized pre-engagement reconnaissance under scope agreement",
        "authorization_confirmed": True
    })
    assert resp.status_code == 201
    inv = resp.json()
    assert inv["target"] == "example.com"
    inv_id = inv["id"]

    # 2. Add note
    note_resp = client.post(f"/api/osint/investigations/{inv_id}/notes", json={
        "author": "Analyst Bob",
        "note": "Primary target domain is active in DNS root."
    })
    assert note_resp.status_code == 200
    assert note_resp.json()["note"] == "Primary target domain is active in DNS root."

    # 3. Mock RDAP lookup to verify intelligence record ingestion
    fake_rdap = {
        "success": True,
        "target": "example.com",
        "target_type": "domain",
        "registrar": "IANA Registry Services",
        "creation_date": "1995-08-14T04:00:00Z",
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        "source_url": "https://rdap.org/domain/example.com"
    }
    with patch("app.api.routes.osint.execute_rdap_whois_lookup", return_value=fake_rdap):
        scan_resp = client.post(f"/api/osint/investigations/{inv_id}/scan", json={
            "tool": "whois_rdap",
            "authorization_confirmed": True
        })
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["status"] == "success"
        assert scan_data["result"]["registrar"] == "IANA Registry Services"

    # 4. Detail view has records
    detail_resp = client.get(f"/api/osint/investigations/{inv_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert len(detail["records"]) >= 1
    assert detail["records"][0]["tool"] == "whois_rdap"
    assert detail["records"][0]["is_live"] is True

    # 5. Export investigation
    export_resp = client.get(f"/api/osint/investigations/{inv_id}/export")
    assert export_resp.status_code == 200
    export_data = export_resp.json()
    assert export_data["investigation_id"] == inv_id
    assert len(export_data["records"]) >= 1

def test_osint_investigation_validation_ip_and_cidr():
    # 1. Valid private IPv4 address (e.g. 192.168.1.40)
    resp = client.post("/api/osint/investigations", json={
        "title": "Internal Gateway Audit",
        "target": "192.168.1.40",
        "target_type": "ip",
        "investigation_purpose": "Authorized internal perimeter triage",
        "authorization_confirmed": True
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["target"] == "192.168.1.40"
    assert data["target_type"] == "ip"

    # 2. Valid CIDR subnet (e.g. 10.0.0.0/24)
    resp_cidr = client.post("/api/osint/investigations", json={
        "title": "Subnet Audit",
        "target": "10.0.0.0/24",
        "target_type": "ip",
        "investigation_purpose": "Authorized CIDR assessment",
        "authorization_confirmed": True
    })
    assert resp_cidr.status_code == 201
    assert resp_cidr.json()["target"] == "10.0.0.0/24"

    # 3. Invalid IP format
    resp_bad_ip = client.post("/api/osint/investigations", json={
        "title": "Bad IP Test",
        "target": "999.123.456.789",
        "target_type": "ip",
        "investigation_purpose": "Test invalid input rejection",
        "authorization_confirmed": True
    })
    assert resp_bad_ip.status_code == 400
    assert "Invalid IP address or CIDR" in resp_bad_ip.json()["detail"]

def test_osint_investigation_domain_validation():
    # 1. Invalid domain format
    resp_bad = client.post("/api/osint/investigations", json={
        "title": "Bad Domain",
        "target": "not a domain!!",
        "target_type": "domain",
        "investigation_purpose": "Test domain validation",
        "authorization_confirmed": True
    })
    assert resp_bad.status_code == 400
    assert "Invalid domain format" in resp_bad.json()["detail"]

    # 2. URL format stripped to domain
    resp_url = client.post("/api/osint/investigations", json={
        "title": "URL Sanitization",
        "target": "https://cybermonkey.io/path",
        "target_type": "domain",
        "investigation_purpose": "Test stripping protocol",
        "authorization_confirmed": True
    })
    assert resp_url.status_code == 201
    assert resp_url.json()["target"] == "cybermonkey.io"

def test_osint_private_ip_rfc1918_recon_handling():
    # Create private IP investigation (192.168.1.40)
    resp = client.post("/api/osint/investigations", json={
        "title": "Local Host 192.168.1.40",
        "target": "192.168.1.40",
        "target_type": "ip",
        "investigation_purpose": "Local subnet investigation",
        "authorization_confirmed": True
    })
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 1. RDAP / WHOIS on private IP gracefully creates RFC 1918 record
    rdap_resp = client.post(f"/api/osint/investigations/{inv_id}/scan", json={
        "tool": "whois_rdap",
        "authorization_confirmed": True
    })
    assert rdap_resp.status_code == 200
    rdap_data = rdap_resp.json()
    assert rdap_data["result"]["is_private"] is True
    assert "RFC 1918" in rdap_data["result"]["rfc_standard"]

    # 2. Shodan on private IP is rejected with clear explanation
    shodan_resp = client.post(f"/api/osint/investigations/{inv_id}/scan", json={
        "tool": "shodan",
        "authorization_confirmed": True
    })
    assert shodan_resp.status_code == 400
    assert "private local IP" in shodan_resp.json()["detail"]

    # 3. Subfinder on IP target is rejected with domain requirement
    sub_resp = client.post(f"/api/osint/investigations/{inv_id}/scan", json={
        "tool": "subfinder",
        "authorization_confirmed": True
    })
    assert sub_resp.status_code == 400
    assert "domain target" in sub_resp.json()["detail"]
