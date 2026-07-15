import os
import re
import json
from typing import List, Dict, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
import google.generativeai as genai
from fpdf import FPDF

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.cisa_kev import CisaKev
from backend.app.models.epss import Epss
from backend.app.prompts.templates import (
    MITRE_MAPPING_PROMPT, 
    PATCH_PRIORITIZATION_PROMPT, 
    INCIDENT_RESPONSE_PROMPT
)

# Initialize Gemini Client if API key is provided
is_gemini_available = False
if settings.GEMINI_API_KEY:
    try:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        is_gemini_available = True
        logger.info("Google Gemini API client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Gemini API client: {str(e)}")

# Safe read-only SQL patterns
SQL_BLACKLIST = re.compile(
    r"\b(update|delete|insert|drop|truncate|alter|create|grant|revoke|replace|merge|execute|dbcc|exec|union\s+all|union)\b", 
    re.IGNORECASE
)

# RAG DB Schema Prompt
DB_SCHEMA_PROMPT = """
You are the database parser for an AI SOC Assistant. Your job is to translate a user's natural language cybersecurity question into a single, syntactically correct PostgreSQL SELECT query.

Here is the database schema:

1. Table: users
   - id: INT (PK)
   - username: VARCHAR(50)
   - email: VARCHAR(100)
   - role: VARCHAR(20) -- 'Admin', 'Analyst', 'Viewer'
   - is_active: BOOLEAN

2. Table: vendors
   - id: INT (PK)
   - name: VARCHAR(100) -- e.g. 'Microsoft', 'Apache', 'Cisco', 'Linux', 'Google'

3. Table: products
   - id: INT (PK)
   - vendor_id: INT (FK references vendors.id)
   - name: VARCHAR(100) -- e.g. 'Windows Server', 'Chrome', 'Log4j', 'Linux Kernel'

4. Table: vulnerabilities
   - cve_id: VARCHAR(30) (PK) -- e.g. 'CVE-2021-44228'
   - title: VARCHAR(255)
   - description: TEXT
   - cvss_score: NUMERIC(3, 1) -- 0.0 to 10.0
   - cvss_vector: VARCHAR(100)
   - severity: VARCHAR(15) -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
   - published_date: TIMESTAMP WITH TIME ZONE
   - last_modified_date: TIMESTAMP WITH TIME ZONE
   - vendor_id: INT (FK references vendors.id)
   - product_id: INT (FK references products.id)

5. Table: cisa_kev
   - cve_id: VARCHAR(30) (PK, FK references vulnerabilities.cve_id)
   - date_added: DATE
   - due_date: DATE
   - action_required: TEXT
   - short_description: TEXT

6. Table: epss
   - cve_id: VARCHAR(30) (PK, FK references vulnerabilities.cve_id)
   - score: NUMERIC(6, 5) -- 0.0 to 1.0 (exploit probability)
   - percentile: NUMERIC(6, 5) -- 0.0 to 1.0

7. Table: ai_analysis
   - id: INT (PK)
   - cve_id: VARCHAR(30) (FK references vulnerabilities.cve_id, UNIQUE)
   - executive_summary: TEXT
   - technical_analysis: TEXT
   - risk_impact: TEXT
   - recommendations: TEXT
   - patch_priority: VARCHAR(15) -- 'IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW'

8. Table: workflow_logs
   - id: INT (PK)
   - source: VARCHAR(100) -- e.g. 'NVD Collector', 'CISA KEV Sync'
   - action_type: VARCHAR(100)
   - status: VARCHAR(20) -- 'SUCCESS', 'FAILED'
   - details: TEXT
   - created_at: TIMESTAMP WITH TIME ZONE

9. Table: audit_logs
   - id: INT (PK)
   - user_id: INT (FK references users.id)
   - action: VARCHAR(100)
   - resource: VARCHAR(100)
   - details: TEXT
   - ip_address: VARCHAR(45)

Guidelines for query generation:
- Write ONLY a valid, standard PostgreSQL SELECT query.
- Use explicit JOINs if filtering by vendor or product name (e.g. `JOIN vendors v ON vuln.vendor_id = v.id`).
- Do NOT wrap the query in markdown code blocks like ```sql ... ```. Output raw text ONLY.
- Ensure only SELECT operations are performed. Do not write queries that modify data.
- Limit results to a maximum of 25 rows (add `LIMIT 25` to queries returning lists).
- If the question cannot be answered with SQL, return an empty string.

User Question: {question}
SQL Query:"""

def validate_sql_safety(sql: str) -> bool:
    """
    Checks if a generated SQL query is safe and is exclusively a SELECT query.
    Prevents destructive operations.
    """
    stripped = sql.strip().lower()
    if not stripped.startswith("select"):
        return False
    if SQL_BLACKLIST.search(stripped):
        return False
    return True

class ThreatReportPDF(FPDF):
    """
    FPDF layout styling helper to compile professional-looking PDF threat briefings.
    """
    def header(self):
        # Top banner with glassmorphism accent
        self.set_fill_color(22, 28, 45) # Dark charcoal background
        self.rect(0, 0, 210, 30, "F")
        
        # Primary Title
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 5, "AI THREAT INTELLIGENCE SUMMARY", 0, 1, "L")
        
        # Subtitle
        self.set_font("Helvetica", "", 10)
        self.set_text_color(156, 163, 175) # Muted gray
        self.cell(0, 5, f"Date Compiled: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC", 0, 1, "L")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(156, 163, 175)
        self.cell(0, 10, f"Page {self.page_no()} | AI Cybersecurity Platform Confidential", 0, 0, "C")

def generate_pdf_report(reports_data: List[Dict[str, Any]]) -> bytes:
    """
    Generates a beautifully styled enterprise PDF report for a collection of CVEs.
    """
    pdf = ThreatReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title Section
    pdf.set_y(35)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(31, 41, 55) # Dark text
    pdf.cell(0, 10, "Executive Vulnerability Briefing", 0, 1, "C")
    pdf.ln(5)
    
    for item in reports_data:
        vuln = item["vulnerability"]
        analysis = item["analysis"]
        
        # Section Header Box
        pdf.set_fill_color(243, 244, 246) # Light gray block
        pdf.set_text_color(17, 24, 39) # Almost black
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"  Vulnerability: {vuln.cve_id} - {vuln.title or 'N/A'}", 0, 1, "L", fill=True)
        pdf.ln(2)
        
        # Details row (CVSS / Severity / EPSS)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(40, 5, f"CVSS Score: {vuln.cvss_score or 'N/A'}", 0, 0)
        pdf.cell(40, 5, f"Severity: {vuln.severity or 'N/A'}", 0, 0)
        pdf.cell(40, 5, f"EPSS Score: {item.get('epss_score', 'N/A')}", 0, 0)
        pdf.cell(50, 5, f"Active Exploit (KEV): {'YES' if item.get('is_kev') else 'NO'}", 0, 1)
        pdf.ln(3)
        
        # 1. Executive Summary
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(0, 5, "Executive Summary", 0, 1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 4, analysis.get("executive_summary", "N/A"))
        pdf.ln(3)
        
        # 2. Technical Analysis
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(0, 5, "Technical Details", 0, 1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 4, analysis.get("technical_analysis", "N/A"))
        pdf.ln(3)
        
        # 3. Recommendations & Action Plan
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(0, 5, f"Recommendations (Priority: {analysis.get('patch_priority', 'MEDIUM')})", 0, 1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(0, 4, analysis.get("recommendations", "N/A"))
        pdf.ln(10)
        
    return bytes(pdf.output())

def run_gemini_prompt(prompt: str) -> str:
    """
    Executes a standard prompt against Gemini 2.5 Flash. Returns response string.
    """
    if not is_gemini_available:
        raise ValueError("Gemini API key is not configured.")
        
    try:
        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Gemini API invocation error: {str(e)}")
        raise e

def generate_ai_cve_analysis(vuln: Vulnerability, epss_score: float, is_kev: bool) -> dict:
    """
    Constructs a detailed prompting payload for Gemini to generate vulnerability
    reports containing Executive Summary, Technical Details, Risk, and Recommendation items.
    Fallback mocks are provided if Gemini API is offline.
    """
    prompt = f"""
    You are an expert cybersecurity threat intelligence analyst. Produce a formal vulnerability threat analysis for the following vulnerability details:
    
    CVE ID: {vuln.cve_id}
    Title: {vuln.title}
    Description: {vuln.description}
    CVSS Base Score: {vuln.cvss_score}
    CVSS Vector: {vuln.cvss_vector}
    Vulnerability Severity: {vuln.severity}
    EPSS Score: {epss_score} (Probability of exploitation in the next 30 days)
    CISA KEV Status: {"Actively Exploited in the Wild" if is_kev else "Not listed in active exploitation catalog"}
    
    Return the analysis structured EXACTLY in the following JSON format. Do not return any other text, comments or wrapping backticks besides valid JSON:
    {{
        "executive_summary": "Provide a high-level summary of what this vulnerability is and why senior stakeholders should care.",
        "technical_analysis": "Provide a deep dive explanation of the technical exploitation vector, root vulnerabilities, and pathways.",
        "risk_impact": "Describe the operational and data threat profiles. What can the attacker accomplish? (Remote execution, privilege escalation, etc.)",
        "recommendations": "Provide standard patching, network rules, firewall block recommendations, or configurations mitigations.",
        "patch_priority": "One value strictly from: IMMEDIATE, HIGH, MEDIUM, LOW"
    }}
    """
    
    # Try Gemini execution
    if is_gemini_available:
        try:
            resp_text = run_gemini_prompt(prompt)
            # Standardize JSON output parsing (strip potential ```json wrap codeblocks)
            cleaned = re.sub(r"^```json\s*", "", resp_text, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            return json.loads(cleaned)
        except Exception as e:
            logger.warning(f"Failed to generate analysis via Gemini, falling back to mock: {str(e)}")
            
    # Mock fallback logic
    priority = "IMMEDIATE" if (vuln.cvss_score and vuln.cvss_score >= 9.0) or is_kev else "HIGH"
    if vuln.cvss_score and vuln.cvss_score < 7.0:
        priority = "MEDIUM"
    if vuln.cvss_score and vuln.cvss_score < 4.0:
        priority = "LOW"
        
    return {
        "executive_summary": f"This alert addresses {vuln.cve_id} in {vuln.title or 'the target component'}. Given a CVSS score of {vuln.cvss_score or 'N/A'} and KEV status of {is_kev}, security units must evaluate asset exposures immediately.",
        "technical_analysis": f"The technical vulnerability is described as: {vuln.description}. This represents a potential point of entry for attackers seeking to exploit system memory or software logic errors.",
        "risk_impact": f"Risk rating is assessed as {vuln.severity}. Impact includes potential loss of confidentiality, integrity, or availability depending on network exposure and host credentials access.",
        "recommendations": f"1. Apply latest software vendor patches immediately.\n2. Review system access controls and isolate affected subnets.\n3. Enable strict endpoint monitoring for suspicious process indicators.",
        "patch_priority": priority
    }

def ask_soc_assistant(db: Session, question: str, history: List[Dict[str, str]] = []) -> dict:
    """
    Natural Language to SQL (NL2SQL) RAG pipeline.
    1. Translate user question to PostgreSQL SELECT using Gemini.
    2. Validate and execute query safely.
    3. Feed result + history to Gemini to generate final natural language summary.
    Includes mock fallback responses for common queries if Gemini API key is missing.
    """
    sql_query = ""
    query_results = []
    
    # 1. Generate SQL
    if is_gemini_available:
        try:
            formatted_prompt = DB_SCHEMA_PROMPT.format(question=question)
            generated_sql = run_gemini_prompt(formatted_prompt)
            
            # Clean SQL backticks
            cleaned_sql = re.sub(r"^```sql\s*", "", generated_sql, flags=re.IGNORECASE)
            cleaned_sql = re.sub(r"\s*```$", "", cleaned_sql)
            cleaned_sql = cleaned_sql.strip().replace(";", "")
            
            if cleaned_sql and validate_sql_safety(cleaned_sql):
                sql_query = cleaned_sql
                logger.info(f"RAG Assistant generated safe SQL query: {sql_query}")
        except Exception as e:
            logger.warning(f"NL2SQL translation failed: {str(e)}")
            
    # Mock/rules based SQL generator if Gemini is missing or failed
    if not sql_query:
        q_lower = question.lower()
        if "critical" in q_lower:
            sql_query = "SELECT cve_id, title, cvss_score, severity FROM vulnerabilities WHERE cvss_score >= 9.0 OR severity = 'CRITICAL' ORDER BY cvss_score DESC LIMIT 10"
        elif "latest" in q_lower or "today" in q_lower:
            sql_query = "SELECT cve_id, title, cvss_score, severity, published_date FROM vulnerabilities ORDER BY published_date DESC LIMIT 10"
        elif "microsoft" in q_lower:
            sql_query = "SELECT v.cve_id, v.title, v.cvss_score, v.severity FROM vulnerabilities v JOIN vendors vend ON v.vendor_id = vend.id WHERE vend.name ILIKE '%Microsoft%' LIMIT 10"
        elif "cisa" in q_lower or "kev" in q_lower:
            sql_query = "SELECT v.cve_id, v.title, v.cvss_score, k.date_added FROM vulnerabilities v JOIN cisa_kev k ON v.cve_id = k.cve_id LIMIT 10"
        elif "epss" in q_lower:
            sql_query = "SELECT v.cve_id, v.title, e.score, e.percentile FROM vulnerabilities v JOIN epss e ON v.cve_id = e.cve_id ORDER BY e.score DESC LIMIT 10"
        else:
            sql_query = "SELECT cve_id, title, cvss_score, severity FROM vulnerabilities LIMIT 10"
            
    # 2. Execute SQL query safely
    if sql_query and validate_sql_safety(sql_query):
        try:
            res = db.execute(text(sql_query))
            columns = res.keys()
            query_results = [dict(zip(columns, row)) for row in res.fetchall()]
        except Exception as e:
            logger.error(f"Failed to execute RAG SQL query: {str(e)}")
            query_results = [{"error": f"Failed to execute generated query: {str(e)}"}]
            
    # 3. Generate Final Response
    context = f"SQL Query Run: {sql_query}\nQuery Output Data:\n{json.dumps(query_results, default=str)}"
    final_prompt = f"""
    You are an AI SOC Assistant. Answer the user's cybersecurity query using the provided SQL results as context.
    Keep the explanation clear, professional, and actionable for a SOC analyst.
    
    Conversation History:
    {json.dumps(history)}
    
    Context Data:
    {context}
    
    User Query: {question}
    SOC Assistant Response:"""
    
    if is_gemini_available:
        try:
            answer = run_gemini_prompt(final_prompt)
            return {
                "answer": answer,
                "source_query": sql_query,
                "source_data": query_results
            }
        except Exception as e:
            logger.warning(f"Failed to compile response via Gemini: {str(e)}")
            
    # Mock Response Compiler if Gemini offline
    cve_ids_found = [r.get("cve_id") for r in query_results if "cve_id" in r]
    cve_string = ", ".join(cve_ids_found) if cve_ids_found else "no matches"
    
    answer = f"I executed a database search and found the following matching items: {cve_string}. "
    if len(query_results) > 0 and "cve_id" in query_results[0]:
        answer += "\n\nKey Vulnerability Highlights:\n"
        for r in query_results[:5]:
            answer += f"- **{r.get('cve_id')}**: {r.get('title', 'No Title')} (Score: {r.get('cvss_score', r.get('score', 'N/A'))})\n"
    else:
        answer += "No specific vulnerabilities were loaded. Please refine your query filters."
        
    return {
        "answer": answer,
        "source_query": sql_query,
        "source_data": query_results
    }

def get_mitre_mapping(cve_id: str, title: str, description: str, cvss_score: float, severity: str) -> dict:
    """
    Deduces MITRE ATT&CK techniques and recommended detections from a CVE's details.
    Runs via Gemini if active, otherwise falls back to a rule-based mock matching.
    """
    if is_gemini_available:
        try:
            prompt = MITRE_MAPPING_PROMPT.format(
                cve_id=cve_id,
                title=title,
                description=description,
                cvss_score=cvss_score,
                severity=severity
            )
            resp_text = run_gemini_prompt(prompt)
            cleaned = re.sub(r"^```json\s*", "", resp_text, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            return json.loads(cleaned)
        except Exception as e:
            logger.warning(f"MITRE mapping generation failed via Gemini: {str(e)}")
            
    # Mock fallback
    desc_l = description.lower() if description else ""
    techniques = []
    detections = []
    
    if "remote code execution" in desc_l or "execute arbitrary code" in desc_l or "rce" in desc_l:
        techniques.append({"code": "T1190", "name": "Exploit Public-Facing Application"})
        techniques.append({"code": "T1059", "name": "Command and Scripting Interpreter"})
        detections.append("Monitor execution of PowerShell/CMD processes originating from web servers.")
        detections.append("Deploy network IPS rules mapping outbound LDAP/RMI connections.")
    elif "privilege escalation" in desc_l or "escalate privileges" in desc_l or "kernel" in desc_l:
        techniques.append({"code": "T1068", "name": "Exploitation for Privilege Escalation"})
        techniques.append({"code": "T1078", "name": "Valid Accounts"})
        detections.append("Audit security log events tracing local privilege elevation mappings.")
        detections.append("Flag suspicious API calls to OS system kernel drivers.")
    elif "session" in desc_l or "hijack" in desc_l or "bypass" in desc_l:
        techniques.append({"code": "T1539", "name": "Steal Web Session Cookie"})
        techniques.append({"code": "T1556", "name": "Modify Authentication Process"})
        detections.append("Enable anomaly checks tracing active session cookie movements.")
        detections.append("Enforce multi-factor authentication (MFA) validation policies.")
    else:
        techniques.append({"code": "T1203", "name": "Exploitation for Client Execution"})
        detections.append("Monitor client endpoints launching shell commands from PDF/Document viewers.")
        
    return {
        "mapped_techniques": techniques,
        "detections": detections
    }

def generate_patch_prioritization(org_name: str, vulns_list: List[dict]) -> str:
    """
    Generates a patch prioritization ranking report using Gemini,
    with rule-based mock rendering if offline.
    """
    if is_gemini_available:
        try:
            prompt = PATCH_PRIORITIZATION_PROMPT.format(
                org_name=org_name,
                vulns_json=json.dumps(vulns_list, default=str)
            )
            return run_gemini_prompt(prompt)
        except Exception as e:
            logger.warning(f"AI patch prioritization failed via Gemini: {str(e)}")
            
    # Mock fallback report compilation
    # Sort vulns by score (descending) and KEV status
    sorted_vulns = sorted(
        vulns_list, 
        key=lambda x: (x.get("is_kev", False), x.get("cvss_score") or 0.0), 
        reverse=True
    )
    
    report = f"### AI Patch Prioritization Report for {org_name}\n"
    report += f"Generated on: {datetime.now().strftime('%Y-%m-%d')} UTC. Total assets scanned: {len(vulns_list)}.\n\n"
    
    for idx, v in enumerate(sorted_vulns, 1):
        cve = v.get("cve_id")
        score = v.get("cvss_score")
        kev = "YES" if v.get("is_kev") else "NO"
        epss = v.get("epss_score", 0.0)
        
        priority = "IMMEDIATE" if (score and score >= 9.0) or v.get("is_kev") else "HIGH"
        if score and score < 7.0:
            priority = "MEDIUM"
            
        report += f"#### Rank #{idx}: {cve} - {v.get('title', 'N/A')} (Priority: **{priority}**)\n"
        report += f"- **CVSS score**: {score or 'N/A'} | **CISA KEV active**: {kev} | **EPSS score**: {epss:.3%}\n"
        report += f"- **Justification**: "
        if v.get("is_kev"):
            report += "This vulnerability is listed in the CISA KEV catalog as actively exploited in the wild. Attackers are currently leveraging this vector."
        elif score and score >= 9.0:
            report += "This item has a critical CVSS score, representing high remote exploitation risks and zero-privilege pathways."
        else:
            report += "Standard severity exposure requiring scheduled mitigation."
        report += f"\n- **Remediation Plan**: Apply patches within designated SLA ({'24 hours' if priority == 'IMMEDIATE' else '14 days'}).\n\n"
        
    return report

def generate_incident_response_playbook(cve_id: str, title: str, description: str, cvss_score: float, cvss_vector: str, is_kev: bool, epss_score: float) -> str:
    """
    Generates an incident response playbook for a critical CVE,
    with mock fallback templates if offline.
    """
    if is_gemini_available:
        try:
            prompt = INCIDENT_RESPONSE_PROMPT.format(
                cve_id=cve_id,
                title=title,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                is_kev="YES" if is_kev else "NO",
                epss_score=f"{epss_score:.3%}"
            )
            return run_gemini_prompt(prompt)
        except Exception as e:
            logger.warning(f"AI incident response generation failed via Gemini: {str(e)}")
            
    # Mock Playbook
    playbook = f"""# Incident Response Playbook: {cve_id}
*Briefing: {title}*

## 1. Immediate Actions
1. **Network Isolation**: Restrict egress traffic from assets running the affected components.
2. **Process Audit**: Run system commands to list active processes and flag suspicious subprocesses originating from public web directory paths.
3. **Session Revocation**: Revoke active user session tokens in Active Directory and force client re-authentications.

## 2. Snort & Firewall Detection Rules
```snort
# Snort rule mapping suspicious outbound JNDI requests
alert tcp any any -> any [389,636,1099,389,80] (msg:"Suspicious JNDI outbound indicator for {cve_id}"; content:"jndi:"; nocase; sid:1000001; rev:1;)
```

## 3. SIEM Threat Detection Query (Splunk SPL)
```splunk
index=security sourcetype=syslog "jndi" OR "${cve_id}"
| stats count by src_ip, dest_ip, signature
| sort -count
```

## 4. Mitigations & Workarounds
- Set environment system property `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` if updating package version is temporarily delayed.
- Map custom local registry keys to block kernel elevations.

## 5. Prioritized Systems Patching Order
1. Edge routers and public DMZ Webservers (Immediate - 12h SLA).
2. Internal databases and Middleware processors (High - 36h SLA).
3. Client workstation endpoints (Scheduled - 7d SLA).
"""
    return playbook

