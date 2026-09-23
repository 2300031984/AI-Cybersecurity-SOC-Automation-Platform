# Deployment & Setup Verification Guide

## 1. Prerequisites
- Docker and Docker Compose installed.
- A configured .env file based on .env.example.
- Required external API credentials supplied where integrations need them.

## 2. Start the stack
    docker compose up --build -d

## 3. Verify services
Check the containers:
    docker compose ps

Expected application endpoints:
- Streamlit: http://localhost:8501
- FastAPI Swagger: http://localhost:8000/docs
- n8n: http://localhost:5678

## 4. Backend verification
- Open FastAPI Swagger and confirm the API is reachable.
- Verify authentication is required on protected endpoints.
- Verify authorized requests can retrieve vulnerability data.
- Confirm API responses are valid JSON and error responses are handled.

## 5. Dashboard verification
- Open Streamlit.
- Verify login/authentication flow.
- Confirm KPI cards and vulnerability views load.
- Confirm charts render when data is available.
- Confirm API connectivity from the dashboard.

## 6. Threat-intelligence verification
Validate ingestion and persistence for:
- NVD CVE records
- CISA KEV status
- EPSS score and percentile
- Enrichment integrations when credentials are configured

## 7. Automation verification
- Confirm n8n is reachable.
- Verify the intended workflow can execute.
- Verify workflow status/log records are persisted.
- Verify configured alert webhooks receive events when triggered.

## 8. Security verification
- Verify JWT authentication and role checks.
- Verify tenant-scoped queries do not expose another organization's records.
- Verify audit logging for security-relevant actions.
- Never commit real API keys, passwords, JWT secrets, or webhook secrets.

## 9. Final evidence
Record:
- Date/time of the test
- Service tested
- Test case
- Expected result
- Actual result
- Pass/Fail
- Screenshot or log reference

> This guide is a verification checklist; it does not claim that every check has already passed.
