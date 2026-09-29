# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for a suspected security vulnerability.

When reporting a vulnerability, include:
- A clear description of the issue
- Affected component, endpoint, or workflow
- Reproduction steps or proof of concept
- Potential security impact
- Relevant logs or screenshots, with secrets and personal data removed

For responsible disclosure, contact the repository maintainer through the contact method associated with this GitHub repository.

## Testing Safety

This project is intended for authorized security testing and defensive research only. Do not use the platform or its integrations to access systems or data without permission.

For local testing, prefer isolated environments and non-production credentials.

## Secrets

Never commit API keys, passwords, tokens, private keys, database credentials, or environment files containing real secrets. Use environment variables or an appropriate secret-management mechanism instead.

If a secret is accidentally committed, revoke or rotate it immediately and remove it from active configuration.

## Scope

Security reports are most useful when they identify a concrete, reproducible security impact in this project's code, configuration, dependencies, or documented deployment workflow.

## Dependency and Configuration Issues

For dependency vulnerabilities or insecure configuration findings, provide the affected package or component, relevant version information, evidence, and a practical remediation path when available.
