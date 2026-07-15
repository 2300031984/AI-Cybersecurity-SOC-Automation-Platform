import pytest
from fastapi.testclient import TestClient

from backend.app.core.security import get_password_hash, verify_password

def test_password_hashing():
    """
    Test hashing and checking of passwords.
    """
    p_plain = "securitypass123"
    hashed = get_password_hash(p_plain)
    
    assert hashed != p_plain
    assert verify_password(p_plain, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_login_success(client: TestClient):
    """
    Test successful login form authentication returns tokens.
    """
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testadmin", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["role"] == "Admin"

def test_login_failure(client: TestClient):
    """
    Test incorrect password returns 401.
    """
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testadmin", "password": "wrongpassword"}
    )
    assert response.status_code == 401

def test_current_user_unauthorized(client: TestClient):
    """
    Test reading profile without header throws 401.
    """
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401

def test_rbac_restrictions_for_viewer(client: TestClient):
    """
    Test that a Viewer is forbidden (403) from calling admin sync endpoints.
    """
    # 1. Log in as Viewer
    resp_login = client.post(
        "/api/v1/auth/login",
        data={"username": "testviewer", "password": "testpass"}
    )
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Try to hit admin sync endpoint
    resp_sync = client.post("/api/v1/sync/cisa", headers=headers)
    assert resp_sync.status_code == 403
    assert "Access Denied" in resp_sync.json()["detail"]
