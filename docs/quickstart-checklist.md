# Deployment Quickstart Checklist

## Before startup
- [ ] Copy `.env.example` to `.env`.
- [ ] Set a strong PostgreSQL password.
- [ ] Set a high-entropy JWT secret.
- [ ] Configure Gemini and threat-intelligence API keys that are required for enabled integrations.
- [ ] Confirm Docker and Docker Compose are available.

## Start
```bash
docker compose up --build -d
```

## Verify
- FastAPI: `http://localhost:8000/docs`
- Streamlit: `http://localhost:8501`
- n8n: `http://localhost:5678`

## Security checks
- [ ] Confirm `.env` is not committed.
- [ ] Verify authentication before using protected API endpoints.
- [ ] Verify tenant isolation with separate test tenants.
- [ ] Confirm webhook destinations are configured intentionally.
- [ ] Review container logs for startup or credential errors.

## Stop
```bash
docker compose down
```
