# Security Controls

The platform applies multiple security controls across the application stack:

- JWT-based authentication for protected API access.
- Role-based authorization for administrative and analyst workflows.
- Tenant-aware data access to reduce cross-organization exposure.
- Audit logging for security-relevant administrative operations.
- Environment-based handling of external API credentials.
- Threat enrichment using CVE, KEV, EPSS and reputation sources.

These controls should be validated during integration and regression testing.
