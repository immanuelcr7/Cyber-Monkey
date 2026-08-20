import os
# Configure environment variables for testing before importing anything from app
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "testsecret"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import uuid

from app.main import app
from app.database.session import Base, get_db, engine, SessionLocal
from app.services.authorization import is_target_authorized
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

# 1. Create assessment
def test_create_assessment(client):
    response = client.post(
        "/api/assessments/",
        json={
            "name": "External Pentest Alpha",
            "organization": "ACME Corp",
            "assessment_type": "External Network",
            "description": "Black-box pentest",
            "start_date": "2026-08-01",
            "end_date": "2026-08-15"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "External Pentest Alpha"
    assert data["organization"] == "ACME Corp"
    assert data["status"] == "active"
    assert "id" in data

# 2. List assessments
def test_list_assessments(client):
    client.post("/api/assessments/", json={"name": "P1", "assessment_type": "Cloud"})
    client.post("/api/assessments/", json={"name": "P2", "assessment_type": "API"})
    
    response = client.get("/api/assessments/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    names = [a["name"] for a in data]
    assert "P1" in names
    assert "P2" in names

# 3. Get assessment
def test_get_assessment(client):
    create_res = client.post("/api/assessments/", json={"name": "P3", "assessment_type": "Web Application"})
    assessment_id = create_res.json()["id"]
    
    response = client.get(f"/api/assessments/{assessment_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "P3"
    assert "targets" in data
    assert len(data["targets"]) == 0

# 4. Update assessment
def test_update_assessment(client):
    create_res = client.post("/api/assessments/", json={"name": "P4", "assessment_type": "Web Application"})
    assessment_id = create_res.json()["id"]
    
    update_res = client.patch(
        f"/api/assessments/{assessment_id}",
        json={"name": "P4 Updated", "status": "completed"}
    )
    assert update_res.status_code == 200
    data = update_res.json()
    assert data["name"] == "P4 Updated"
    assert data["status"] == "completed"

# 5. Delete assessment
def test_delete_assessment(client):
    create_res = client.post("/api/assessments/", json={"name": "P5", "assessment_type": "Web Application"})
    assessment_id = create_res.json()["id"]
    
    del_res = client.delete(f"/api/assessments/{assessment_id}")
    assert del_res.status_code == 204
    
    get_res = client.get(f"/api/assessments/{assessment_id}")
    assert get_res.status_code == 404

# 6. Create domain target
def test_create_domain_target(client):
    create_res = client.post("/api/assessments/", json={"name": "T1", "assessment_type": "External Network"})
    assessment_id = create_res.json()["id"]
    
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "sub.example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res.status_code == 201
    data = target_res.json()
    assert data["target_type"] == "Domain"
    assert data["target_value"] == "sub.example.com"
    assert data["authorization_confirmed"] is True

# 7. Create IP target
def test_create_ip_target(client):
    create_res = client.post("/api/assessments/", json={"name": "T2", "assessment_type": "External Network"})
    assessment_id = create_res.json()["id"]
    
    # IPv4
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "192.168.1.100",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res.status_code == 201
    
    # IPv6
    target_res_v6 = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "2001:db8::1",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res_v6.status_code == 201

# 8. Create URL target
def test_create_url_target(client):
    create_res = client.post("/api/assessments/", json={"name": "T3", "assessment_type": "Web Application"})
    assessment_id = create_res.json()["id"]
    
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "URL",
            "target_value": "https://example.com/login",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res.status_code == 201

# 9. Reject invalid domain
def test_reject_invalid_domain(client):
    create_res = client.post("/api/assessments/", json={"name": "T4", "assessment_type": "External Network"})
    assessment_id = create_res.json()["id"]
    
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "not_a_domain_##",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res.status_code == 400
    assert "Invalid target value" in target_res.json()["detail"]

# 10. Reject invalid IP
def test_reject_invalid_ip(client):
    create_res = client.post("/api/assessments/", json={"name": "T5", "assessment_type": "External Network"})
    assessment_id = create_res.json()["id"]
    
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "IP Address",
            "target_value": "999.888.777.666",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res.status_code == 400
    assert "Invalid target value" in target_res.json()["detail"]

# 11. Reject invalid URL
def test_reject_invalid_url(client):
    create_res = client.post("/api/assessments/", json={"name": "T6", "assessment_type": "Web Application"})
    assessment_id = create_res.json()["id"]
    
    # FTP scheme is not http/https
    target_res_ftp = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "URL",
            "target_value": "ftp://example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res_ftp.status_code == 400

    # No domain/host
    target_res_nohost = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "URL",
            "target_value": "https:///path/without/host",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert target_res_nohost.status_code == 400

# 12. Verify target belongs to assessment
def test_target_belongs_to_assessment(client):
    a1 = client.post("/api/assessments/", json={"name": "A1", "assessment_type": "API"}).json()
    a2 = client.post("/api/assessments/", json={"name": "A2", "assessment_type": "API"}).json()
    
    target = client.post(
        f"/api/assessments/{a1['id']}/targets",
        json={
            "target_type": "Domain",
            "target_value": "api.example.com",
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    ).json()
    
    # Fetch from assessment 1
    t1_list = client.get(f"/api/assessments/{a1['id']}/targets").json()
    assert len(t1_list) == 1
    assert t1_list[0]["id"] == target["id"]
    
    # Fetch from assessment 2
    t2_list = client.get(f"/api/assessments/{a2['id']}/targets").json()
    assert len(t2_list) == 0

# 13. Verify authorization helper
def test_verify_authorization_helper():
    t_authorized = Target(
        scope_status="in_scope",
        authorization_confirmed=True
    )
    assert is_target_authorized(t_authorized) is True

# 14. Verify out-of-scope target is not authorized
def test_verify_out_of_scope_unauthorized():
    t_out_of_scope = Target(
        scope_status="out_of_scope",
        authorization_confirmed=True
    )
    assert is_target_authorized(t_out_of_scope) is False

# 15. Verify unauthorized target is not authorized
def test_verify_unconfirmed_unauthorized():
    t_unconfirmed = Target(
        scope_status="in_scope",
        authorization_confirmed=False
    )
    assert is_target_authorized(t_unconfirmed) is False

# 16. Verify target update authorization validation
def test_update_target_authorization(client):
    create_res = client.post("/api/assessments/", json={"name": "T7", "assessment_type": "External Network"})
    assessment_id = create_res.json()["id"]
    
    # Create an out_of_scope target (doesn't require authorization confirmation)
    target_res = client.post(
        f"/api/assessments/{assessment_id}/targets",
        json={
            "target_type": "Domain",
            "target_value": "out.example.com",
            "scope_status": "out_of_scope",
            "authorization_confirmed": False
        }
    )
    assert target_res.status_code == 201
    target_id = target_res.json()["id"]
    
    # Try updating it to in_scope without confirming authorization
    patch_res = client.patch(
        f"/api/targets/{target_id}",
        json={
            "scope_status": "in_scope"
        }
    )
    assert patch_res.status_code == 400
    assert "Authorization confirmation is required" in patch_res.json()["detail"]
    
    # Try updating it with authorization confirmed
    patch_res_ok = client.patch(
        f"/api/targets/{target_id}",
        json={
            "scope_status": "in_scope",
            "authorization_confirmed": True
        }
    )
    assert patch_res_ok.status_code == 200
    assert patch_res_ok.json()["scope_status"] == "in_scope"
    assert patch_res_ok.json()["authorization_confirmed"] is True
    
    # Try changing authorization_confirmed to False while remaining in_scope
    patch_res_fail = client.patch(
        f"/api/targets/{target_id}",
        json={
            "authorization_confirmed": False
        }
    )
    assert patch_res_fail.status_code == 400
    assert "Authorization confirmation is required" in patch_res_fail.json()["detail"]
