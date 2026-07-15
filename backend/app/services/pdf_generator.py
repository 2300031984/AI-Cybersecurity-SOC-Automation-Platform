from fpdf import FPDF
from datetime import datetime
from typing import List, Dict, Any

class SOCReportPDF(FPDF):
    def header(self):
        # Draw dark-mode style header band
        self.set_fill_color(22, 27, 34) # GitHub Dark Canvas color
        self.rect(0, 0, 210, 40, "F")
        
        self.set_text_color(88, 166, 255) # Light Blue Accent
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "AI CYBERSECURITY THREAT INTELLIGENCE PLATFORM", ln=True, align="C")
        
        self.set_text_color(240, 246, 252) # Off-White text
        self.set_font("Helvetica", "I", 10)
        self.cell(0, 10, f"SOC Daily Briefing Report  |  Tenant Context  |  Generated: {datetime.now().strftime('%Y-%m-%d')} UTC", ln=True, align="C")
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(139, 148, 158)
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}}  |  CONFIDENTIAL - SOC OPERATIONS USE ONLY", align="C")

def compile_soc_daily_report(org_name: str, reports_data: List[Dict[str, Any]]) -> bytes:
    """
    Compiles a comprehensive PDF SOC briefing document for the organization.
    """
    pdf = SOCReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.ln(10)

    # Executive Overview section
    pdf.set_text_color(240, 246, 252)
    pdf.set_fill_color(33, 38, 45) # Dark Grey fill for sections
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f" 1. Executive Summary for {org_name}", fill=True, ln=True)
    pdf.ln(4)
    
    pdf.set_text_color(40, 40, 40) # Standard black for printing compatibility
    pdf.set_font("Helvetica", "", 10)
    summary_text = (
        f"This automated brief summarizes active security exposures, vulnerabilities, and prioritized threat intelligence "
        f"for {org_name}. Telemetry feeds from the National Vulnerability Database (NVD), CISA's Known Exploited "
        f"Vulnerabilities (KEV) Catalog, and the Exploit Prediction Scoring System (EPSS) have been parsed on-the-fly "
        f"and structured using automated AI reasoning."
    )
    pdf.multi_cell(0, 6, summary_text)
    pdf.ln(8)

    # Top Threats Summary
    pdf.set_text_color(240, 246, 252)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, " 2. Critical Vulnerabilities & Threat Exposures", fill=True, ln=True)
    pdf.ln(4)

    for item in reports_data:
        v = item["vulnerability"]
        a = item["analysis"]
        is_kev_str = "YES (Active in the Wild)" if item["is_kev"] else "NO"
        
        pdf.set_text_color(220, 53, 69) # Red color for CVE headers
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"{v.cve_id}: {v.title or 'No Title Supplied'}", ln=True)
        
        # Metrics line
        pdf.set_text_color(40, 40, 40)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(40, 6, f"CVSS Score: {v.cvss_score or 'N/A'}")
        pdf.cell(40, 6, f"Severity: {v.severity}")
        pdf.cell(50, 6, f"CISA KEV Active: {is_kev_str}")
        pdf.cell(45, 6, f"EPSS Score: {item['epss_score']:.3%}", ln=True)
        
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Vector: {v.cvss_vector or 'N/A'}", ln=True)
        pdf.ln(2)

        # AI Summary block
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, "AI Risk Analysis Justification:", ln=True)
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5, a.get("executive_summary", "No AI analysis compiled."))
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, "Mitigations & Patch Plan:", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, a.get("recommendations", "Apply standard system updates."))
        
        pdf.ln(6)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y()) # separator line
        pdf.ln(4)

    # Appendix section
    pdf.set_text_color(240, 246, 252)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, " 3. SOC Audit Appendix", fill=True, ln=True)
    pdf.ln(4)
    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "", 9)
    appendix_text = (
        "Classification: CONFIDENTIAL. This report contains sensitive infrastructure risk profiles. "
        "Store securely and restrict distribution to active Security Operations Center engineers, "
        "remediation team leads, and compliance auditors."
    )
    pdf.multi_cell(0, 5, appendix_text)

    return pdf.output(dest="S")
