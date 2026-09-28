# Release Checklist

Use this checklist before creating a release or deployment.

## Application

- [ ] Backend starts successfully.
- [ ] Dashboard starts successfully.
- [ ] Database migrations have been reviewed.
- [ ] Environment variables are configured.
- [ ] No secrets are committed.

## Security

- [ ] Authentication tests pass.
- [ ] Authorization and tenant isolation are verified.
- [ ] API input validation is enabled.
- [ ] Security headers and TLS configuration are reviewed.
- [ ] Production debug settings are disabled.

## Testing

- [ ] Backend test suite passes.
- [ ] Database tests pass.
- [ ] Workflow tests pass.
- [ ] Critical API paths have been manually smoke-tested.
- [ ] Deployment verification has been completed.

## Documentation

- [ ] README reflects the current architecture.
- [ ] Security policy is current.
- [ ] Changelog includes release-relevant changes.
- [ ] Demo and deployment instructions are current.
