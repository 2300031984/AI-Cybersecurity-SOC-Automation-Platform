# Final Testing Checklist

## Application
- [ ] Docker Compose stack starts successfully.
- [ ] FastAPI is reachable through the configured endpoint.
- [ ] Streamlit dashboard loads successfully.
- [ ] n8n is reachable and workflows can be opened.
- [ ] PostgreSQL is healthy and persistent data is available.

## Authentication & Authorization
- [ ] Login/token generation works with valid credentials.
- [ ] Protected endpoints reject unauthenticated requests.
- [ ] Invalid or expired tokens are rejected.
- [ ] Role-based permissions are enforced for Viewer, Analyst, Manager, and Admin flows.

## Threat Intelligence
- [ ] NVD CVE ingestion can be executed.
- [ ] CISA KEV enrichment is stored correctly.
- [ ] EPSS score and percentile are stored correctly.
- [ ] Duplicate vulnerability records are handled correctly.
- [ ] Enrichment integrations behave correctly when credentials are unavailable.

## AI / RAG
- [ ] AI analysis returns the expected structured fields.
- [ ] Generated SQL is restricted to the intended read-only operation.
- [ ] Unsafe SQL keywords/operations are rejected.
- [ ] RAG responses contain the expected database context.

## Multi-Tenant Security
- [ ] Users can access only records belonging to their organization.
- [ ] Cross-tenant vulnerability access is rejected.
- [ ] Cross-tenant AI analysis access is rejected.
- [ ] Audit/workflow records retain organization context.

## Dashboard
- [ ] KPI metrics load correctly.
- [ ] Vulnerability search/filtering works.
- [ ] Severity and EPSS visualizations render with available data.
- [ ] AI/security views handle empty datasets without crashing.

## Automation & Alerts
- [ ] n8n ingestion workflow executes successfully.
- [ ] Workflow status is logged.
- [ ] Alert webhook configuration is validated.
- [ ] Failed integrations produce useful error/status information.

## Evidence
For each executed test, record the date, test case, expected result, actual result, Pass/Fail status, and supporting screenshot or log reference.
