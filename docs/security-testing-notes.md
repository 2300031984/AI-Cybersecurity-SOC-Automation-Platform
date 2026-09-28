# Security Testing Notes

This project should be validated in an isolated development environment before deployment.

## Authentication

- Verify valid credentials are accepted.
- Verify invalid credentials are rejected.
- Verify protected endpoints reject unauthenticated requests.
- Verify expired or invalid JWTs are rejected.
- Verify authorization remains tenant-aware.

## API security

- Validate request schemas and reject unexpected or malformed input.
- Confirm tenant identifiers cannot be changed through client-controlled fields.
- Check that object-level authorization is enforced for every protected resource.
- Avoid exposing secrets or internal stack traces in API responses.

## Data protection

- Keep credentials in environment variables or a secrets manager.
- Apply database-level tenant isolation where configured.
- Review logs to ensure passwords, tokens, and API keys are never recorded.

## Test discipline

Run security tests against local or explicitly authorized environments only. Record reproducible evidence for confirmed findings and avoid destructive or state-changing tests on production systems.
