-- AI Cybersecurity Threat Intelligence & SOC Automation Platform (v2.0)
-- Database Schema Definition (PostgreSQL)

-- Clean up existing tables
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS workflow_logs CASCADE;
DROP TABLE IF EXISTS workflow_execution_logs CASCADE;
DROP TABLE IF EXISTS ai_analysis CASCADE;
DROP TABLE IF EXISTS epss CASCADE;
DROP TABLE IF EXISTS cisa_kev CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS vendors CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;

-- 1. Organizations Table (Multi-Tenancy)
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(500) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users Table (Multi-Tenant RBAC)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE, -- NULL represents system-wide admin
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('Admin', 'Analyst', 'Manager', 'Viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Vendors Table
CREATE TABLE vendors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(500) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Products Table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    vendor_id INT REFERENCES vendors(id) ON DELETE CASCADE,
    name VARCHAR(500) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vendor_id, name)
);

-- 5. Vulnerabilities Table (Tenant-specific asset exposure mapping)
CREATE TABLE vulnerabilities (
    cve_id VARCHAR(30) PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE, -- Isolates vulnerabilities to tenant context
    title VARCHAR(500),
    description TEXT,
    cvss_score NUMERIC(3, 1),
    cvss_vector VARCHAR(100),
    severity VARCHAR(15) CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    published_date TIMESTAMP WITH TIME ZONE,
    last_modified_date TIMESTAMP WITH TIME ZONE,
    vendor_id INT REFERENCES vendors(id) ON DELETE SET NULL,
    product_id INT REFERENCES products(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. CISA KEV (Known Exploited Vulnerabilities) Table
CREATE TABLE cisa_kev (
    cve_id VARCHAR(30) PRIMARY KEY REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    date_added DATE NOT NULL,
    due_date DATE,
    action_required TEXT NOT NULL,
    short_description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. EPSS (Exploit Prediction Scoring System) Table
CREATE TABLE epss (
    cve_id VARCHAR(30) PRIMARY KEY REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    score NUMERIC(6, 5) NOT NULL,
    percentile NUMERIC(6, 5) NOT NULL,
    retrieved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. AI Vulnerability Analysis Reports Table
CREATE TABLE ai_analysis (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    executive_summary TEXT NOT NULL,
    technical_analysis TEXT NOT NULL,
    risk_impact TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    patch_priority VARCHAR(15) CHECK (patch_priority IN ('IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW')),
    generated_by INT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Automation Workflow Execution Logs
CREATE TABLE workflow_logs (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    source VARCHAR(100) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('SUCCESS', 'FAILED')),
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9b. n8n Automation Workflow Execution Logs
CREATE TABLE workflow_execution_logs (
    id SERIAL PRIMARY KEY,
    workflow_name VARCHAR(255),
    execution_id VARCHAR(255),
    status VARCHAR(50),
    processed_items INTEGER,
    failed_node VARCHAR(255),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. Enterprise Audit Logs
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Query Optimization Indexes
CREATE INDEX idx_vuln_org ON vulnerabilities(organization_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_cvss ON vulnerabilities(cvss_score);
CREATE INDEX idx_vuln_pub_date ON vulnerabilities(published_date);
CREATE INDEX idx_vuln_vendor ON vulnerabilities(vendor_id);
CREATE INDEX idx_vuln_product ON vulnerabilities(product_id);
CREATE INDEX idx_epss_score ON epss(score);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_workflow_source ON workflow_logs(source);
