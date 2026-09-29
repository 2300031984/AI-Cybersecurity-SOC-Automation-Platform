# Release Checklist

## Application

- [ ] Run backend tests.
- [ ] Validate database migrations/schema.
- [ ] Verify authentication and authorization.
- [ ] Confirm tenant isolation/RLS behavior.
- [ ] Validate API responses and error handling.

## Threat intelligence

- [ ] Verify NVD/EPSS ingestion.
- [ ] Verify CISA KEV enrichment.
- [ ] Verify MITRE ATT&CK enrichment.
- [ ] Confirm duplicate handling.
- [ ] Confirm failed external feeds are handled safely.

## AI and automation

- [ ] Validate Gemini prompt and response parsing.
- [ ] Confirm AI output is schema-validated.
- [ ] Test n8n workflow execution.
- [ ] Verify alert integrations before enabling production notifications.

## Deployment

- [ ] Remove development secrets and debug settings.
- [ ] Configure production environment variables.
- [ ] Review logs for sensitive data.
- [ ] Back up the database.
- [ ] Document the release version and rollback procedure.
