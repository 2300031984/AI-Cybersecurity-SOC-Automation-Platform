# Portfolio & Presentation Assets (v2.0 - Phase 4)

This document compiles career-enhancing portfolio assets, interview guides, and scripts relating to the upgraded AI Cybersecurity Threat Intelligence & SOC Automation Platform (v2.0).

---

## 1. Professional Resume Bullet Points

*   **Senior Security Engineer / Backend & AI Integrations**:
    *   Designed and built a multi-tenant, production-ready AI Threat Intelligence & SOC Automation Platform integrating Python (FastAPI), PostgreSQL, and Google Gemini 2.5 Flash.
    *   Implemented strict row-level tenant isolation in the FastAPI/SQLAlchemy database layer, ensuring users mapped to Microsoft, Amazon, Infosys, TCS, or Deloitte can only browse and search organization-specific exposures.
    *   Created a modular, LangChain-based RAG Security Copilot utilizing `ConversationBufferMemory` to maintain conversation thread context and enable multi-turn dialogues on CVE exposures.
    *   Engineered a secure Natural-Language-to-SQL (NL2SQL) translation service utilizing regex command sanitizers that restrict AI-generated SQL query execution strictly to safe `SELECT` operations.
    *   Developed an automated AI Patch Prioritizer ranking organizational vulnerabilities on-the-fly based on CVSS score severity, CISA KEV exploit status, and EPSS score exploit likelihoods.
    *   Designed an AI Incident Response Playbook compiler that generates immediate containment checklists, Snort firewall rules, and Splunk SPL SIEM threat hunting queries.
    *   Integrated multi-source IOC reputation threat feeds from VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX, with automated mock fallbacks to handle API key rate limits gracefully.
    *   Constructed a complete Pytest integration suite confirming JWT authentication, RBAC restrictions (Admin, Analyst, Manager, Viewer), and tenant query filtering isolation boundaries.

---

## 2. High-Impact LinkedIn Announcement Post

```text
🚀 Exciting Project Share! I have just launched the Enterprise upgrade (v2.0) of my "AI Cybersecurity Threat Intelligence & SOC Automation Platform" — an enterprise-grade multi-tenant threat center.

What's New in v2.0:
🔹 Multi-Tenant Isolation: Complete row-level database segregation supporting separate organization contexts (Microsoft, Amazon, TCS, Deloitte).
🔹 AI Security Copilot (RAG): Modular LangChain-based chat assistant that queries PostgreSQL tables, maintains conversation memory, and displays SQL debug queries.
🔹 AI Patch Prioritization: Automatically ranks vulnerability lists from highest to lowest patch priority using CVSS, CISA KEV, and EPSS scores.
🔹 AI Incident Response: Generates containment playbooks, Snort firewall rules, and Splunk threat detection queries for critical CVEs.
🔹 Multi-Source IOC Enrichment: Real-time reputational assessment of IPs, domains, hashes, and URLs (VirusTotal, AbuseIPDB, URLhaus, OTX).

Tech Stack:
🔹 Automation: n8n Workflow Engine
🔹 AI Engine: Google Gemini 2.5 Flash + LangChain
🔹 Backend API: Python, FastAPI, SQLAlchemy, Pydantic v2
🔹 UI Dashboard: Streamlit (Multi-page configuration), Plotly Charts
🔹 Database: PostgreSQL with optimized indexes & foreign keys
🔹 Containerization: Docker & Docker Compose

Check out the full repository here: [Github Repo URL Placeholder]

#cybersecurity #ai #fastapi #python #rag #threatintelligence #soc #docker #multitenant #langchain
```

---

## 3. PPT Presentation Outline Slides

*   **Slide 1: Title & Overview**
    *   *Title*: Enterprise AI Security Platform (v2.0)
    *   *Subtitle*: Scaling Threat Intelligence & SOC Automation with Multi-Tenancy and LangChain RAG
*   **Slide 2: The Multi-Tenant Problem & Solution**
    *   *Problem*: MSPs and MSSPs need to manage vulnerability profiles for multiple organizations securely without sharing data across boundaries.
    *   *Solution*: Strict SQLAlchemy query-layer isolation filters queries dynamically based on the analyst's logged-in `organization_id`.
*   **Slide 3: Technical Architecture**
    *   *Diagram description*: Nginx Reverse Proxy routing to Streamlit front-end and FastAPI backend. FastAPI isolates data queries via PostgreSQL and queries external feeds (NVD, CISA KEV, EPSS, MITRE) and Google Gemini (via LangChain).
*   **Slide 4: LangChain RAG Security Copilot**
    *   *Key Features*: Analyst-focused chat interface; dynamic NL-to-SQL translation with regex safety checks; conversation memory buffers; backend debug panel showing SQL statements and query returns.
*   **Slide 5: Risk-Driven Patch Prioritization**
    *   *Approach*: Leverages real-time EPSS exploit probability data and CISA KEV active threat indicators to calculate a logical patching order, reducing organizational remediation SLAs.
*   **Slide 6: AI-Powered Incident Response Playbooks**
    *   *Capabilities*: Generates instant playbooks for critical threats, delivering iptables/Snort rules, Splunk SPL queries, and network containment instructions.
*   **Slide 7: IOC Assessment & Threat Feed Enrichment**
    *   *Telemetry sources*: Integrates AbuseIPDB, VirusTotal, URLhaus, and AlienVault OTX. Features mock responders to simulate operations when API keys are absent.
*   **Slide 8: Demo & Wrap Up**
    *   *Summary*: Multi-tenant analyst login; Plotly risk trend dashboards; SOC Copilot queries; incident containment exports.

---

## 4. Live Demo Walkthrough Script

*   **Intro (0:00 - 0:30)**:
    "Hello everyone. Today I'm demonstrating the Enterprise AI Security Platform v2.0. This multi-tenant dashboard is built with FastAPI, PostgreSQL, Streamlit, and Google Gemini."
*   **Multi-Tenant Login & Overview (0:30 - 1:15)**:
    "First, we log in using Microsoft credentials (`analyst@microsoft.local`). The overview dashboard loads, displaying Microsoft-specific metrics: total vulnerabilities, critical entries, and average EPSS score. The alert queue lists Microsoft's active vulnerabilities. If we were to log out and log in as Amazon analyst, we would see a completely different set of vulnerabilities and metrics."
*   **Threat Explorer & MITRE Mapping (1:15 - 2:00)**:
    "Next, on the Threats search page, we can search by keyword or filter by severity, CVSS score, and KEV status. Selecting a vulnerability like CVE-2021-44228 retrieves its description, EPSS score, and automatically displays AI-derived MITRE ATT&CK technique codes along with recommended SOC detection rules."
*   **AI Report, Prioritization, & IR Playbook (2:00 - 3:00)**:
    "On the AI Reports page, we have three tabs. We can compile Daily briefings to PDF or HTML, click 'Generate Prioritized Patch Schedule' to rank all vulnerabilities by risk priority, or select a critical CVE to generate an instant Incident Response Playbook containing containment steps, Snort rules, and Splunk Splunk queries."
*   **IOC Enrichment (3:00 - 3:30)**:
    "On the IOC Enrichment page, SOC analysts can perform reputation lookups on IPs, file hashes, domains, and URLs. The backend queries VirusTotal, AbuseIPDB, and URLhaus to assess indicator risk."
*   **LangChain RAG Security Copilot (3:30 - 4:15)**:
    "Finally, the RAG Security Copilot chatbot lets analysts ask natural language questions. We can expand the sidebar debug inspector to inspect the safe SQL query generated by LangChain and the raw database response."

---

## 5. Technical Interview Q&A (STAR Method)

### Question 1: How did you implement multi-tenant data isolation securely at the software layer?
*   **Situation**: I needed to upgrade the platform to support multi-tenancy, preventing users from different companies from seeing each other's security logs and vulnerability records.
*   **Task**: I had to ensure complete row-level isolation while avoiding complex database partition schemas that would slow down development.
*   **Action**: I added an `organizations` table and mapped `organization_id` foreign keys to the users, vulnerabilities, and reports tables. In the FastAPI backend, I updated the dependency guard `get_current_user` to validate the user's organization. Inside the API routers, I injected SQLAlchemy filters `.filter(Vulnerability.organization_id == current_user.organization_id)` if the user belongs to a tenant.
*   **Result**: This safely isolated threat data per tenant. A global system admin can still view all data, while corporate tenant analysts can only query their own records.

### Question 2: How did you handle API rate limits and key exhaustion when querying external threat feeds?
*   **Situation**: Integrating third-party reputation lookups like VirusTotal or AbuseIPDB introduces rate limit issues, especially when executing multiple lookups in a busy SOC.
*   **Task**: I needed to ensure that threat lookups did not crash or block dashboard rendering when API limits were exceeded or keys were missing.
*   **Action**: I designed a dual-mode service layer in `threat_enrichment.py`. The class attempts live HTTP requests if the API keys are configured. If they are absent, it falls back to a rule-based mock responder returning simulated, high-fidelity threat reports (e.g. flagging specific test IP ranges as malicious and others as safe).
*   **Result**: This guaranteed 100% uptime for local testing, user demos, and testing suites, while enabling real-world connections in production.
