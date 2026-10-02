# Threat Triage Workflow

The platform combines vulnerability and threat-intelligence signals to help analysts prioritize security work.

## Triage flow

1. **Collect** — ingest CVE and threat-intelligence records.
2. **Normalize** — store common vulnerability fields, severity, affected products, and enrichment data.
3. **Enrich** — correlate CISA KEV, EPSS, MITRE ATT&CK, and available reputation sources.
4. **Prioritize** — consider severity together with exploitation evidence and likelihood signals.
5. **Analyze** — use the AI security layer for contextual analysis and remediation guidance.
6. **Review** — an analyst validates the result before taking operational action.
7. **Respond** — apply the appropriate remediation or containment playbook.
8. **Audit** — retain relevant actions and outcomes for traceability.

## Analyst principle

AI-generated recommendations are decision support, not automatic authorization for destructive or state-changing actions. Analysts should validate affected assets, evidence, scope, and business impact before response actions.

## Useful signals

| Signal | Purpose |
|---|---|
| CVSS / severity | Estimate technical impact |
| CISA KEV | Identify vulnerabilities known to be exploited |
| EPSS | Estimate exploitation likelihood |
| MITRE ATT&CK | Add adversary-technique context |
| Reputation feeds | Enrich IOC context |
