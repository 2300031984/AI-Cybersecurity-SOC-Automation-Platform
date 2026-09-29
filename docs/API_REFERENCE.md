# API Quick Reference

## FastAPI service

Default local URL: `http://localhost:8000`

### Core endpoints

- `GET /api/v1/vulnerabilities` — retrieve vulnerability intelligence records.
- `GET /api/v1/analysis` — retrieve AI-driven security analysis.
- `GET /docs` — FastAPI Swagger/OpenAPI documentation.

## Request flow

1. n8n collects vulnerability and threat-intelligence data.
2. Intelligence is normalized and enriched.
3. Gemini analyzes the collected context.
4. Results are persisted in PostgreSQL.
5. FastAPI exposes the stored intelligence.
6. Streamlit presents the results to analysts.

## Authentication

Protected API routes require the configured authentication mechanism and valid credentials/token. Do not place secrets in source code or commit them to Git.
