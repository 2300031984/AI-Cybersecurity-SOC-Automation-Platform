import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.vulnerability import Vulnerability
from backend.app.core.security import get_password_hash

def get_auth_headers(client: TestClient, username: str) -> dict:
    """Helper to log in a user and return request headers."""
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": "testpass"}
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_get_vulnerabilities(client: TestClient, db: Session):
    """
    Test reading vulnerability lists.
    """
    headers = get_auth_headers(client, "testviewer")
    
    # Check initial empty list
    response = client.get("/api/v1/vulnerabilities", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 0
    
    # Add a vulnerability
    v = Vulnerability(
        cve_id="CVE-2023-0001",
        title="Test Vuln",
        description="Description test",
        cvss_score=8.0,
        severity="HIGH"
    )
    db.add(v)
    db.commit()
    
    # Verify loaded
    response = client.get("/api/v1/vulnerabilities", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["cve_id"] == "CVE-2023-0001"

def test_get_dashboard_summary(client: TestClient, db: Session):
    """
    Test retrieving KPI dashboard summary metrics.
    """
    headers = get_auth_headers(client, "testviewer")
    
    # Add metrics values
    v1 = Vulnerability(cve_id="CVE-2023-1111", title="V1", cvss_score=9.5, severity="CRITICAL")
    v2 = Vulnerability(cve_id="CVE-2023-2222", title="V2", cvss_score=7.0, severity="HIGH")
    db.add_all([v1, v2])
    db.commit()
    
    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_vulnerabilities"] == 2
    assert data["critical_vulnerabilities"] == 1
    assert data["high_vulnerabilities"] == 1

def test_soc_assistant_chat(client: TestClient):
    """
    Test conversational SOC Chat Assistant endpoint (RAG).
    """
    headers = get_auth_headers(client, "testanalyst")
    
    response = client.post(
        "/api/v1/chat",
        json={"message": "Show critical Microsoft vulnerabilities", "history": []},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "source_query" in data
    assert isinstance(data["source_data"], list)

def test_multi_tenant_isolation(client: TestClient, db: Session):
    """
    Verify that row-level tenant isolation isolates vulnerabilities.
    """
    from backend.app.models.organization import Organization
    from backend.app.models.user import User
    
    # 1. Create Organizations
    org_a = Organization(id=10, name="Tenant A")
    org_b = Organization(id=20, name="Tenant B")
    db.add_all([org_a, org_b])
    db.commit()
    
    # 2. Create Users mapped to organizations
    user_a = User(
        username="user_a",
        email="a@tenant.local",
        hashed_password=get_password_hash("testpass"),
        role="Analyst",
        organization_id=10,
        is_active=True
    )
    user_b = User(
        username="user_b",
        email="b@tenant.local",
        hashed_password=get_password_hash("testpass"),
        role="Analyst",
        organization_id=20,
        is_active=True
    )
    db.add_all([user_a, user_b])
    db.commit()
    
    # 3. Create vulnerabilities belonging to different tenants
    vuln_a = Vulnerability(
        cve_id="CVE-2026-9991",
        organization_id=10,
        title="Tenant A Exploit",
        cvss_score=9.8,
        severity="CRITICAL"
    )
    vuln_b = Vulnerability(
        cve_id="CVE-2026-9992",
        organization_id=20,
        title="Tenant B Exploit",
        cvss_score=8.5,
        severity="HIGH"
    )
    db.add_all([vuln_a, vuln_b])
    db.commit()
    
    # 4. Access as User A
    headers_a = get_auth_headers(client, "user_a")
    resp_a = client.get("/api/v1/vulnerabilities", headers=headers_a)
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert len(data_a) == 1
    assert data_a[0]["cve_id"] == "CVE-2026-9991"
    
    # 5. Access as User B
    headers_b = get_auth_headers(client, "user_b")
    resp_b = client.get("/api/v1/vulnerabilities", headers=headers_b)
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert len(data_b) == 1
    assert data_b[0]["cve_id"] == "CVE-2026-9992"

