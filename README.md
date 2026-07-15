# AI Cybersecurity Threat Intelligence & SOC Automation Platform (v2.0 - Phase 4)

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=flat&logo=streamlit)](https://streamlit.io)
[![n8n](https://img.shields.io/badge/Automation-n8n-FF6C37?style=flat&logo=n8n)](https://n8n.io)
[![Google Gemini](https://img.shields.io/badge/AI-Google_Gemini-4285F4?style=flat&logo=google)](https://ai.google.dev)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Containers-Docker_Compose-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A production-ready, multi-tenant enterprise **AI Cybersecurity Threat Intelligence and SOC Automation Platform**. The platform aggregates live threat data feeds (NVD CVE registry, CISA KEV catalog, EPSS likelihood indexes), performs row-level tenant isolation, and delivers advanced AI-powered remediation playbooks and security chat features.

---

## 🚀 Key Features

*   **Multi-Tenant Isolation**: Implements strict row-level database segregation using SQLAlchemy query filters. Users logged into separate companies (Microsoft, Amazon, TCS, Deloitte, Infosys) can only access organization-specific vulnerability lists.
*   **Vulnerability Data Normalization**: Fully normalized PostgreSQL schemas mapping vulnerabilities, products, vendors, CISA KEV details, and EPSS scores to organization assets.
*   **AI Security Copilot (LangChain RAG)**: Features a conversational security assistant powered by LangChain. It dynamically translates natural language queries into safe SQL SELECT queries, maintains thread memory, and displays SQL compilation logs.
*   **AI Patch Prioritization**: Automatically prioritizes and ranks organizational vulnerability exposures based on CVSS severity, CISA KEV exploit status, and EPSS exploit probability scores.
*   **AI Incident Response Playbook Compiler**: Instantly compiles containment playbooks containing immediate mitigation instructions, Snort firewall rules, and Splunk SPL queries.
*   **IOC Enrichment Feeds**: Interfaces with VirusTotal, AbuseIPDB, URLhaus, and AlienVault OTX to perform reputation lookups on IPs, hashes, domains, and URLs (with automatic mock fallbacks if keys are absent).
*   **Real-Time NVD Resolvers**: Dynamically fetches and saves unindexed CVE profiles from the official NVD API.
*   **JWT RBAC Authorization**: Enforces role constraints supporting `Admin` (Sync controls, logs), `Analyst` (AI reports, chat), `Manager` (Patch schedules, playbooks), and `Viewer` (Read-only statistics).

---

## 🛠️ Technology Stack

*   **Automation**: n8n
*   **AI Engine**: Google Gemini 2.5 Flash + LangChain
*   **Backend**: Python 3.11, FastAPI, SQLAlchemy, Pydantic v2
*   **Dashboard**: Streamlit (Multi-page configuration), Plotly Charts
*   **Database**: PostgreSQL 15, SQL DDL
*   **Containerization**: Docker, Docker Compose
*   **Documentation & Assets**: Markdown, Mermaid, FPDF2

---

## 📦 Quick Start In 60 Seconds

### Prerequisites
*   Docker & Docker Compose installed.
*   A Google Gemini API key (Optional; uses fallback mocks if absent).

### Setup Instructions
1.  Clone the repository.
2.  Copy `.env.example` to `.env`:
    ```bash
    cp .env.example .env
    ```
3.  Edit `.env` and paste your API keys:
    ```env
    GEMINI_API_KEY=AIzaSy...
    VIRUSTOTAL_API_KEY=...
    ABUSEIPDB_API_KEY=...
    ```
4.  Build and start the multi-container stack:
    ```bash
    docker compose up --build -d
    ```

### Access Ports
*   **Streamlit Web Interface**: [http://localhost:8501](http://localhost:8501)
*   **FastAPI API Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
*   **n8n Workflow Panel**: [http://localhost:5678](http://localhost:5678)

---

## 👥 Seeded Tenant User Profiles
Log in to the Streamlit Dashboard using these predefined credentials:

| Tenant | Username  | Password   | Role | Permissions Profile |
| :--- | :-------- | :--------- | :--- | :------------------ |
| **Microsoft** | `admin`   | `admin123` | **Admin**   | Full access, database trigger collector syncs, logs |
| **Microsoft** | `analyst` | `analyst123`| **Analyst** | Trigger AI reports, use RAG Chat Assistant |
| **Microsoft** | `manager` | `manager123`| **Manager** | View statistics, run patch priorities and playbooks |
| **Microsoft** | `viewer`  | `viewer123`| **Viewer**  | Read-only stats tables and metric dashboards |
| **Amazon** | `amazon_analyst` | `analyst123` | **Analyst** | Access Amazon-specific threat feeds and RAG Copilot |
| **Amazon** | `amazon_viewer`  | `viewer123`  | **Viewer**  | Read-only stats tables and metrics for Amazon only |

---

## 📄 License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
