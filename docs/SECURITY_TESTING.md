# Security Testing Notes

## Testing scope

The platform should be tested in an isolated development environment before production deployment.

### Application security

- Validate authentication and authorization on protected API routes.
- Verify tenant isolation and PostgreSQL Row-Level Security policies.
- Test input validation and error handling.
- Check for insecure direct object references and authorization bypasses.
- Verify secrets are supplied through environment variables.

### API testing

Use the OpenAPI specification at `/docs` to enumerate intended endpoints, then test:

- Authentication failures
- Authorization boundaries
- Malformed JSON and unexpected types
- Rate and resource limits
- Sensitive data exposure
- CORS behavior

### Data and AI pipeline

Validate that:

- Threat-intelligence records retain their tenant context.
- Duplicate detection does not discard unrelated records.
- AI output is parsed and validated before persistence.
- External API failures do not corrupt stored data.
- Prompt/input data cannot inject unauthorized application actions.

Only test systems and assets for which you have explicit authorization.
