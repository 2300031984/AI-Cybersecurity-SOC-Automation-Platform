import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.workflow_logs import WorkflowExecutionLog
from tests.test_backend.test_api import get_auth_headers

def test_create_workflow_execution_log(client: TestClient, db: Session):
    """
    Test creating a workflow execution log with standard auth headers.
    """
    headers = get_auth_headers(client, "testadmin")
    payload = {
        "workflow_name": "SOC Threat Intelligence Pipeline",
        "execution_id": "12345",
        "status": "SUCCESS",
        "processed_items": 200,
        "failed_node": None,
        "error_message": None
    }
    
    response = client.post("/api/v1/workflow/log", json=payload, headers=headers)
    assert response.status_code == 201
    
    data = response.json()
    assert data["workflow_name"] == "SOC Threat Intelligence Pipeline"
    assert data["execution_id"] == "12345"
    assert data["status"] == "SUCCESS"
    assert data["processed_items"] == 200
    assert data["failed_node"] is None
    assert data["error_message"] is None
    assert "id" in data
    assert "created_at" in data

    # Verify storage in DB
    db_log = db.query(WorkflowExecutionLog).filter(WorkflowExecutionLog.execution_id == "12345").first()
    assert db_log is not None
    assert db_log.workflow_name == "SOC Threat Intelligence Pipeline"

def test_create_workflow_execution_log_master_token(client: TestClient, db: Session):
    """
    Test creating a workflow execution log using the master bypass token.
    """
    # Use the master bypass token
    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3ODQxMDQxMTcsInN1YiI6IjEiLCJ0eXBlIjoiYWNjZXNzIn0.Jtt-afSPoz4tOk0VL04nWRbh8ZHxer61KKjXMU5DRvk"
    }
    payload = {
        "workflow_name": "SOC Threat Intelligence Pipeline Master Bypass",
        "execution_id": "99999",
        "status": "FAILED",
        "processed_items": 5,
        "failed_node": "Gemini Enrichment Node",
        "error_message": "Rate limit exceeded"
    }
    
    response = client.post("/api/v1/workflow/log", json=payload, headers=headers)
    assert response.status_code == 201
    
    data = response.json()
    assert data["workflow_name"] == "SOC Threat Intelligence Pipeline Master Bypass"
    assert data["execution_id"] == "99999"
    assert data["status"] == "FAILED"
    assert data["processed_items"] == 5
    assert data["failed_node"] == "Gemini Enrichment Node"
    assert data["error_message"] == "Rate limit exceeded"

    # Verify storage in DB
    db_log = db.query(WorkflowExecutionLog).filter(WorkflowExecutionLog.execution_id == "99999").first()
    assert db_log is not None
    assert db_log.status == "FAILED"

def test_create_workflow_execution_log_unauthenticated(client: TestClient):
    """
    Verify request fails with 401 UNAUTHORIZED when no token is provided.
    """
    payload = {
        "workflow_name": "SOC Threat Intelligence Pipeline",
        "execution_id": "12345",
        "status": "SUCCESS",
        "processed_items": 200,
        "failed_node": None,
        "error_message": None
    }
    response = client.post("/api/v1/workflow/log", json=payload)
    assert response.status_code == 401
