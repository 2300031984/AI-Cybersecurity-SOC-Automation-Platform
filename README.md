# AI Cybersecurity Threat Intelligence & SOC Automation Platform (v2.0 - Phase 20)

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=flat&logo=streamlit)](https://streamlit.io)
[![n8n](https://img.shields.io/badge/Automation-n8n-FF6C37?style=flat&logo=n8n)](https://n8n.io)
[![Google Gemini](https://img.shields.io/badge/AI-Google_Gemini-4285F4?style=flat&logo=google)](https://ai.google.dev)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Containers-Docker_Compose-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade AI-powered Security Operations Center (SOC) automation platform that combines threat intelligence, SOAR automation, vulnerability management, and AI-driven security analysis.

The platform automatically collects vulnerabilities, enriches threat intelligence, calculates risk, generates security reports, and delivers real-time SOC alerts. Aggregating live threat data feeds (NVD CVE registry, CISA KEV catalog, EPSS likelihood indexes), it performs row-level tenant isolation and delivers AI-powered remediation playbooks and security chat features.

---

## 🏗️ Architecture

### Core Components
- **FastAPI Backend**: Powering REST APIs, database orchestration, and security analysis.
- **PostgreSQL Database**: Secure data store for threats, metrics, logs, and user metadata.
- **Streamlit SOC Dashboard**: Single-pane visual analyst workspace.
- **n8n SOAR Automation Engine**: Automated orchestrator triggering threat sync runs and alert webhooks.
- **Gemini AI Security Copilot**: AI engine for security analysis, prioritization, and RAG-assisted workflows.
- **Threat Intelligence APIs**: Live threat telemetry and enrichment lookups.

### System Diagram
```text
Threat Sources
      │
      ▼
NVD / EPSS / CISA KEV / VirusTotal / AbuseIPDB
      │
      ▼
n8n Automation
      │
      ▼
FastAPI Backend
      │
      ▼
PostgreSQL
      │
      ▼
Streamlit Dashboard
```

Detailed diagrams and visual flows are available in the [Architecture Documentation](docs/architecture.md).

---

## 🚀 Key Features

### Threat Intelligence & SOAR
* **Multi-Tenant Isolation**: Implements tenant-aware data segregation using application-level query controls and database isolation mechanisms.
* **Vulnerability Data Normalization**: Normalized PostgreSQL schemas for vulnerabilities, products, vendors, CISA KEV details, and EPSS scores.
* **IOC Enrichment Feeds**: Interfaces with VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX for reputation lookups, with fallback handling when keys are unavailable.
* **NVD Resolvers**: Dynamically fetches and saves CVE profiles from the official NVD API.
* **MITRE ATT&CK Mapping**: Maps vulnerability exposure context to adversarial techniques.

### AI & Security Copilot
* **AI Security Copilot (LangChain RAG)**: Conversational security assistance with retrieval-augmented context.
* **AI Patch Prioritization**: Prioritizes vulnerability exposures using severity, KEV status, and EPSS signals.
* **AI Incident Response Playbooks**: Generates structured containment and remediation guidance.

### Enterprise Security
* **JWT RBAC Authorization**: Role-based access controls for administrative, analyst, manager, and viewer workflows.
* **Audit Logging**: Records security-relevant administrative operations for traceability.

---

## 🛠️ Technology Stack

- **Backend**: FastAPI, SQLAlchemy, Python 3.11, Pydantic v2
- **Automation**: n8n SOAR
- **AI Engine**: Google Gemini, LangChain, RAG
- **Dashboard**: Streamlit, Plotly Express
- **Database**: PostgreSQL 15
- **Feeds & Integration**: NVD, EPSS, CISA KEV, MITRE ATT&CK, VirusTotal, AbuseIPDB
- **Containerization**: Docker, Docker Compose
- **Documentation**: Markdown, Mermaid

---

## 📦 Running the Project

### Prerequisites
* Docker & Docker Compose installed.
* A Google Gemini API key (optional; fallback behavior is available where implemented).

### Setup Instructions
1. **Clone** the repository:
   ```bash
   git clone https://github.com/2300031984/AI-Cybersecurity-SOC-Automation-Platform.git
   ```
2. **Configure** environment parameters:
   ```bash
   cp .env.example .env
   ```
3. **Edit** `.env` and provide the required integration keys.
4. **Start** the multi-container stack:
   ```bash
   docker compose up --build -d
   ```

### Access Ports & Services
* **Streamlit Web Interface**: http://localhost:8501
* **FastAPI API Swagger Docs**: http://localhost:8000/docs
* **n8n Workflow Panel**: http://localhost:5678

---

## 📄 Project Status

### Completed Work
- **Phase 1–7**: Core architecture, threat intelligence ingestion, SOAR automation, AI analysis, dashboard implementation, enterprise security controls, and testing foundations.
- **Phase 8–19**: Extended integration, data enrichment, tenant-aware workflows, AI/RAG capabilities, dashboard refinements, and validation.
- **Phase 20**: Final testing and stabilization.

**Current Status**: Final testing and stabilization.

---

## 📄 License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
