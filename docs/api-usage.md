# API Usage Notes

The FastAPI service exposes interactive API documentation at:

`http://localhost:8000/docs`

## Authentication

Protected endpoints require the application's configured authentication mechanism. Obtain a valid token through the supported authentication flow and provide it using the API client's authorization controls.

## Vulnerability workflow

A typical analyst workflow is:

1. Authenticate.
2. Request vulnerability records.
3. Filter or inspect records relevant to the tenant.
4. Review enrichment such as EPSS and KEV status.
5. Send selected findings through the analysis workflow.
6. Review the resulting recommendation before operational response.

## Example request shape

Use the Swagger UI to inspect the exact schemas exposed by the running version rather than relying on hard-coded payloads in documentation. This keeps examples aligned with the deployed API contract.

## Operational notes

- Never place JWTs or API keys in source control.
- Use tenant-scoped credentials for testing.
- Treat AI output as analyst assistance and validate security actions before execution.
- Use low-risk test data when validating integrations.
