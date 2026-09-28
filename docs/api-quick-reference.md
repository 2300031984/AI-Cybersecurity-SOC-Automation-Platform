# API Quick Reference

The FastAPI backend exposes versioned endpoints under `/api/v1`.

## Core endpoints

- `GET /api/v1/vulnerabilities` — retrieve vulnerability records.
- `GET /api/v1/analysis` — retrieve AI security analysis data.
- Authentication endpoints are provided under `/api/v1/auth`.
- Workflow operations are provided under `/api/v1/workflow`.
- Threat enrichment is provided under `/api/v1/enrichment`.

## Local development

Start the backend on port 8000 and open the FastAPI-generated documentation at:

```
http://127.0.0.1:8000/docs
```

Authentication should be configured according to the environment variables documented in `.env.example`.

## Security notes

Do not commit production credentials, API keys, JWT secrets, or third-party service tokens. Use the example environment file as the starting point for local configuration.
