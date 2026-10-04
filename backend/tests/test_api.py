import os
import tempfile

with tempfile.NamedTemporaryFile(prefix="cipherops-test-", suffix=".db", delete=False) as _db_file:
    _db_path = _db_file.name
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///" + _db_path
os.environ["JWT_SECRET"] = "test-only-secret-with-more-than-32-characters"
os.environ["CORS_ORIGINS"] = "http://testserver"

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import seed_demo
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AuditLog, Incident, Role, User
from app.security import hash_password


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        with SessionLocal() as db:
            analyst_role = db.scalar(select(Role).where(Role.name == "SOC Analyst"))
            admin_role = db.scalar(select(Role).where(Role.name == "Security Administrator"))
            db.add_all(
                [
                    User(
                        email="analyst@test.example",
                        full_name="Test Analyst",
                        password_hash=hash_password("test-password-123"),
                        roles=[analyst_role],
                    ),
                    User(
                        email="admin@test.example",
                        full_name="Test Admin",
                        password_hash=hash_password("test-password-123"),
                        roles=[admin_role],
                    ),
                    User(
                        email="mfa@test.example",
                        full_name="MFA Analyst",
                        password_hash=hash_password("test-password-123"),
                        roles=[analyst_role],
                    ),
                    Incident(
                        incident_key="INC-TEST",
                        title="Test incident",
                        severity="Critical",
                        risk_score=90,
                        status="Investigating",
                        source="Test",
                        asset_count=2,
                        owner="analyst@test.example",
                    ),
                ]
            )
            db.commit()
        yield test_client
    engine.dispose()
    os.unlink(_db_path)


def token_for(client, email="analyst@test.example"):
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "test-password-123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_and_current_user(client):
    token = token_for(client)
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["roles"] == ["SOC Analyst"]


def test_bad_credentials_are_rejected(client):
    response = client.post(
        "/api/v1/auth/login", json={"email": "analyst@test.example", "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_totp_setup_verification_and_login_requirement(client):
    token = token_for(client, "mfa@test.example")
    headers = {"Authorization": f"Bearer {token}"}
    setup = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()
    enabled = client.post("/api/v1/auth/mfa/verify", headers=headers, json={"code": code})
    assert enabled.status_code == 200
    without_code = client.post(
        "/api/v1/auth/login", json={"email": "mfa@test.example", "password": "test-password-123"}
    )
    assert without_code.status_code == 401
    valid = pyotp.TOTP(secret).now()
    with_code = client.post(
        "/api/v1/auth/login",
        json={"email": "mfa@test.example", "password": "test-password-123", "mfa_code": valid},
    )
    assert with_code.status_code == 200
    disabled = client.post(
        "/api/v1/auth/mfa/disable", headers=headers, json={"code": pyotp.TOTP(secret).now()}
    )
    assert disabled.status_code == 200


def test_incidents_and_dashboard_require_auth_and_return_database_rows(client):
    assert client.get("/api/v1/incidents").status_code == 401
    token = token_for(client)
    headers = {"Authorization": f"Bearer {token}"}
    rows = client.get("/api/v1/incidents", headers=headers)
    assert rows.status_code == 200
    assert rows.json()[0]["incident_key"] == "INC-TEST"
    summary = client.get("/api/v1/dashboard/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["critical_incidents"] == 1


def test_admin_endpoints_enforce_rbac_and_write_audit(client):
    analyst_token = token_for(client)
    denied = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {analyst_token}"})
    assert denied.status_code == 403
    admin_token = token_for(client, "admin@test.example")
    created = client.post(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "email": "new@test.example",
            "full_name": "New Analyst",
            "password": "test-password-456",
            "role": "SOC Analyst",
        },
    )
    assert created.status_code == 201
    assert created.json()["email"] == "new@test.example"
    incident = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "New test incident created",
            "severity": "High",
            "risk_score": 75,
            "asset_count": 2,
        },
    )
    assert incident.status_code == 201
    assert incident.json()["incident_key"] == "INC-1025"
    with SessionLocal() as db:
        assert (
            db.scalar(select(AuditLog).where(AuditLog.action == "admin.user_created")) is not None
        )


def test_demo_seed_is_repeatable_and_uses_no_repository_password(monkeypatch, client):
    monkeypatch.setattr(seed_demo, "getpass", lambda _: "a-long-demo-password")
    seed_demo.main()
    seed_demo.main()
    with SessionLocal() as db:
        assert db.query(Incident).count() == 22
        assert db.query(User).filter(User.email == "raja.jamal@northstar.example").count() == 1
