# System Architecture & Diagrams Documentation

This document compiles the Mermaid system diagrams mapping out the AI Cybersecurity Threat Intelligence & SOC Automation Platform.

---

## 1. System Architecture Diagram
Illustrates the container relationships, service layout, reverse proxy configurations, and external integrations.

```mermaid
graph TD
    User([Security Analyst / Admin]) -->|HTTP Port 80| Nginx[Nginx Reverse Proxy]
    
    subgraph Containerized Application Sandbox
        Nginx -->|Proxy /| Streamlit[Streamlit Dashboard: 8501]
        Nginx -->|Proxy /api| FastAPI[FastAPI Backend: 8000]
        
        Streamlit -->|API Queries| FastAPI
        
        FastAPI -->|ORM queries| Postgres[(PostgreSQL Database: 5432)]
        n8n[n8n Automation Engine: 5678] -->|Ingestion Commands| FastAPI
    end
    
    subgraph External Integrations
        FastAPI -->|Rest API Queries| NVD[NVD API Feed]
        FastAPI -->|JSON Feeds| CISA[CISA KEV Catalog]
        FastAPI -->|Gzip Feeds| EPSS[First.org EPSS scores]
        FastAPI -->|AI prompt queries| Gemini[Google Gemini 2.5 Flash]
        n8n -->|Webhooks| Slack[Slack Alert Channel]
    end
    
    classDef container fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef db fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef ext fill:#1c1917,stroke:#78716c,stroke-width:2px,color:#fff;
    
    class Streamlit,FastAPI,n8n,Nginx container;
    class Postgres db;
    class NVD,CISA,EPSS,Gemini,Slack ext;
```

---

## 2. Relational Entity Relationship (ER) Diagram
Maps out the normalized tables, structural schemas, data types, indexes, and primary/foreign keys.

```mermaid
erDiagram
    organizations {
        int id PK
        string name UNIQUE
        timestamp created_at
    }
    users {
        int id PK
        int organization_id FK
        string username UNIQUE
        string email UNIQUE
        string hashed_password
        string role
        boolean is_active
        timestamp created_at
    }
    vendors {
        int id PK
        string name UNIQUE
    }
    products {
        int id PK
        int vendor_id FK
        string name
    }
    vulnerabilities {
        string cve_id PK
        int organization_id FK
        string title
        string description
        numeric cvss_score
        string cvss_vector
        string severity
        int vendor_id FK
        int product_id FK
        timestamp published_date
    }
    cisa_kev {
        string cve_id PK_FK
        date date_added
        date due_date
        string action_required
        string short_description
    }
    epss {
        string cve_id PK_FK
        numeric score
        numeric percentile
        timestamp retrieved_at
    }
    ai_analysis {
        int id PK
        string cve_id FK_UNIQUE
        int organization_id FK
        string executive_summary
        string technical_analysis
        string risk_impact
        string recommendations
        string patch_priority
        int generated_by FK
    }
    workflow_logs {
        int id PK
        int organization_id FK
        string source
        string action_type
        string status
        string details
        timestamp created_at
    }
    audit_logs {
        int id PK
        int organization_id FK
        int user_id FK
        string action
        string resource
        string details
        string ip_address
        timestamp created_at
    }

    organizations ||--o{ users : "owns"
    organizations ||--o{ vulnerabilities : "contains"
    organizations ||--o{ ai_analysis : "contains"
    organizations ||--o{ workflow_logs : "records"
    organizations ||--o{ audit_logs : "contains"
    vendors ||--o{ products : "manufactures"
    vendors ||--o{ vulnerabilities : "discovers"
    products ||--o{ vulnerabilities : "contains"
    vulnerabilities ||--o| cisa_kev : "has_exploit"
    vulnerabilities ||--o| epss : "has_score"
    vulnerabilities ||--o| ai_analysis : "contains_ai_report"
    users ||--o{ ai_analysis : "generates"
    users ||--o{ audit_logs : "triggers"
```

---

## 3. Sequence Diagram (AI SOC Chat Inquiries)
Traces the operations of a user running a conversational SQL RAG assistant threat query.

```mermaid
sequenceDiagram
    actor User as SOC Analyst
    participant Dash as Streamlit Dashboard
    participant API as FastAPI Backend
    participant Gemini as Google Gemini API
    participant DB as PostgreSQL DB
    
    User ->> Dash: Enters Natural Language Question\n"Show Microsoft critical CVEs"
    Dash ->> API: POST /api/v1/chat {message, history}
    API ->> Gemini: Requests SQL query translation based on DB schema
    Gemini -->> API: Returns raw safe SQL query:\n"SELECT cve_id, title FROM vulnerabilities..."
    API ->> API: Sanitizes and checks SQL query syntax safety (SELECT only)
    API ->> DB: Executes generated SELECT query
    DB -->> API: Returns context rows dataset
    API ->> Gemini: Sends user query + history + query dataset context
    Gemini -->> API: Compiles summarized natural language response
    API ->> Dash: Returns {answer, source_query, source_data}
    Dash ->> User: Displays response text + generated SQL code + raw tables
```

---

## 4. Ingestion Data Flow Diagram
Maps out the data pipeline ingestion flows, from data source feeds to database storage.

```mermaid
graph LR
    subgraph Data Sources
        cisa_feed[CISA KEV JSON Feed]
        epss_feed[First.org EPSS Gzip Feed]
        nvd_feed[NVD API Registry]
    end
    
    subgraph Collector Service
        parser[threat_intel.py sync services]
    end
    
    subgraph Database
        db_vuln[(Vulnerabilities Table)]
        db_kev[(CisaKev Table)]
        db_epss[(Epss Table)]
        db_logs[(Workflow Logs)]
    end
    
    cisa_feed -->|Fetch & Ingest| parser
    epss_feed -->|Download & Parse Gzip| parser
    nvd_feed -->|Query CVE profiles| parser
    
    parser -->|Normalize & Save| db_vuln
    parser -->|Link Exploit Info| db_kev
    parser -->|Update score parameters| db_epss
    parser -->|Log Run statuses| db_logs
```

---

## 5. Use Case Diagram
Describes the target user persona scopes and access rights.

```mermaid
graph TD
    subgraph Use Cases
        uc_kpi[View KPI Charts & Stats]
        uc_search[Search & Resolve CVEs]
        uc_report[Trigger AI Threat Briefings]
        uc_chat[Query RAG SOC Chat Assistant]
        uc_sync[Manual Ingest Feed Update Runs]
        uc_audit[Inspect User Audit Logs]
    end
    
    Viewer((Viewer Role))
    Analyst((Analyst Role))
    Manager((Manager Role))
    Admin((Admin Role))
    
    Viewer --> uc_kpi
    Viewer --> uc_search
    
    Analyst --> uc_kpi
    Analyst --> uc_search
    Analyst --> uc_report
    Analyst --> uc_chat
    
    Manager --> uc_kpi
    Manager --> uc_search
    Manager --> uc_report
    
    Admin --> uc_kpi
    Admin --> uc_search
    Admin --> uc_report
    Admin --> uc_chat
    Admin --> uc_sync
    Admin --> uc_audit
```
