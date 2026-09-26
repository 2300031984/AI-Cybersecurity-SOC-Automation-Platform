# Contributing

## Before You Start

1. Read the project README and understand the service architecture.
2. Create changes on a dedicated branch when working locally.
3. Never commit secrets or production credentials.
4. Keep changes focused and document security-sensitive behavior.

## Development Guidelines

- Prefer small, reviewable commits.
- Keep API and database changes backward-compatible where practical.
- Add or update tests when behavior changes.
- Validate Docker Compose configuration before submitting deployment-related changes.
- Update documentation when setup, configuration, or security behavior changes.

## Security

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Pull Requests

A useful pull request should explain:
- What changed
- Why it changed
- How it was tested
- Any security or deployment considerations
