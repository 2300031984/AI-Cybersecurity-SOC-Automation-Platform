from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session
from typing import List

from backend.app.database.session import get_db
from backend.app.api.deps import get_current_user, RoleChecker
from backend.app.models.user import User
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.ai_analysis import AIAnalysis
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.ai_analysis import AIAnalysisCreate, ReportRequest
from backend.app.schemas.vulnerability import AIAnalysisOut
from backend.app.services.ai_service import generate_ai_cve_analysis, generate_pdf_report
from backend.app.services.pdf_generator import compile_soc_daily_report

router = APIRouter()

# Role guards: Viewer cannot run reports
analyst_or_admin_required = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))

@router.post("/analysis", response_model=AIAnalysisOut, dependencies=[analyst_or_admin_required])
def create_cve_analysis(
    payload: AIAnalysisCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually create or update an AI vulnerability analysis report.
    """
    vuln_query = db.query(Vulnerability).filter(Vulnerability.cve_id == payload.cve_id)
    if current_user.organization_id is not None:
        vuln_query = vuln_query.filter(Vulnerability.organization_id == current_user.organization_id)
    vuln = vuln_query.first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {payload.cve_id} not found in database. Ingest CVE first."
        )
        
    analysis_query = db.query(AIAnalysis).filter(AIAnalysis.cve_id == payload.cve_id)
    if current_user.organization_id is not None:
        analysis_query = analysis_query.filter(AIAnalysis.organization_id == current_user.organization_id)
    analysis = analysis_query.first()
    
    if not analysis:
        analysis = AIAnalysis(
            cve_id=payload.cve_id,
            organization_id=current_user.organization_id,
            executive_summary=payload.executive_summary,
            technical_analysis=payload.technical_analysis,
            risk_impact=payload.risk_impact,
            recommendations=payload.recommendations,
            patch_priority=payload.patch_priority,
            generated_by=current_user.id
        )
        db.add(analysis)
    else:
        analysis.executive_summary = payload.executive_summary
        analysis.technical_analysis = payload.technical_analysis
        analysis.risk_impact = payload.risk_impact
        analysis.recommendations = payload.recommendations
        analysis.patch_priority = payload.patch_priority
        analysis.generated_by = current_user.id
        
    db.commit()
    db.refresh(analysis)
    
    # Audit trail
    audit = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="REPORT_GENERATE",
        resource=f"analysis/{payload.cve_id}",
        details=f"User '{current_user.username}' manually saved AI analysis."
    )
    db.add(audit)
    db.commit()
    
    return analysis

@router.post("/analysis/trigger/{cve_id}", response_model=AIAnalysisOut, dependencies=[analyst_or_admin_required])
def trigger_ai_analysis(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers Gemini (or fallback mock) to analyze a CVE in the database
    and stores the generated report.
    """
    vuln_query = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id)
    if current_user.organization_id is not None:
        vuln_query = vuln_query.filter(Vulnerability.organization_id == current_user.organization_id)
    vuln = vuln_query.first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {cve_id} not found in local database."
        )
        
    epss_score = float(vuln.epss.score) if vuln.epss else 0.0
    is_kev = (vuln.cisa_kev is not None)
    
    ai_result = generate_ai_cve_analysis(vuln, epss_score, is_kev)
    
    analysis_query = db.query(AIAnalysis).filter(AIAnalysis.cve_id == cve_id)
    if current_user.organization_id is not None:
        analysis_query = analysis_query.filter(AIAnalysis.organization_id == current_user.organization_id)
    analysis = analysis_query.first()
    
    if not analysis:
        analysis = AIAnalysis(
            cve_id=cve_id,
            organization_id=current_user.organization_id,
            executive_summary=ai_result["executive_summary"],
            technical_analysis=ai_result["technical_analysis"],
            risk_impact=ai_result["risk_impact"],
            recommendations=ai_result["recommendations"],
            patch_priority=ai_result["patch_priority"],
            generated_by=current_user.id
        )
        db.add(analysis)
    else:
        analysis.executive_summary = ai_result["executive_summary"]
        analysis.technical_analysis = ai_result["technical_analysis"]
        analysis.risk_impact = ai_result["risk_impact"]
        analysis.recommendations = ai_result["recommendations"]
        analysis.patch_priority = ai_result["patch_priority"]
        analysis.generated_by = current_user.id
        
    db.commit()
    db.refresh(analysis)
    
    audit = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="REPORT_GENERATE",
        resource=f"analysis/trigger/{cve_id}",
        details=f"User '{current_user.username}' triggered live Gemini analysis."
    )
    db.add(audit)
    db.commit()
    
    return analysis

@router.post("/analysis/report", dependencies=[analyst_or_admin_required])
def compile_threat_briefing(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Compile a multi-CVE briefing report.
    Returns:
    - PDF attachment (as raw bytes)
    - HTML formatted briefing page
    - Markdown raw briefing document
    """
    reports_data = []
    
    for cve_id in payload.cve_ids:
        vuln_query = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id)
        if current_user.organization_id is not None:
            vuln_query = vuln_query.filter(Vulnerability.organization_id == current_user.organization_id)
        vuln = vuln_query.first()
        
        if not vuln:
            continue
            
        analysis_query = db.query(AIAnalysis).filter(AIAnalysis.cve_id == cve_id)
        if current_user.organization_id is not None:
            analysis_query = analysis_query.filter(AIAnalysis.organization_id == current_user.organization_id)
        analysis = analysis_query.first()
        
        if not analysis:
            # Generate on-the-fly and save
            epss_score = float(vuln.epss.score) if vuln.epss else 0.0
            is_kev = (vuln.cisa_kev is not None)
            ai_res = generate_ai_cve_analysis(vuln, epss_score, is_kev)
            analysis = AIAnalysis(
                cve_id=cve_id,
                organization_id=current_user.organization_id,
                executive_summary=ai_res["executive_summary"],
                technical_analysis=ai_res["technical_analysis"],
                risk_impact=ai_res["risk_impact"],
                recommendations=ai_res["recommendations"],
                patch_priority=ai_res["patch_priority"],
                generated_by=current_user.id
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            
        reports_data.append({
            "vulnerability": vuln,
            "analysis": {
                "executive_summary": analysis.executive_summary,
                "technical_analysis": analysis.technical_analysis,
                "risk_impact": analysis.risk_impact,
                "recommendations": analysis.recommendations,
                "patch_priority": analysis.patch_priority
            },
            "is_kev": vuln.cisa_kev is not None,
            "epss_score": float(vuln.epss.score) if vuln.epss else 0.0
        })
        
    if not reports_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid CVE IDs matching database items were provided."
        )
        
    # Audit trail
    audit = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="REPORT_GENERATE",
        resource="analysis/report",
        details=f"User '{current_user.username}' compiled a multi-CVE {payload.format.upper()} report."
    )
    db.add(audit)
    db.commit()
    
    # PDF generation
    if payload.format.lower() == "pdf":
        org_name = current_user.organization.name if current_user.organization else "Global System Registry"
        pdf_bytes = compile_soc_daily_report(org_name, reports_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=executive_briefing.pdf"
            }
        )
        
    # Markdown generation
    elif payload.format.lower() == "markdown":
        md = f"# AI Vulnerability Threat Briefing\n*Generated by Antigravity AI on behalf of {current_user.username}*\n\n---\n\n"
        for item in reports_data:
            v = item["vulnerability"]
            a = item["analysis"]
            md += f"## {v.cve_id}: {v.title or 'N/A'}\n"
            md += f"- **Severity**: {v.severity or 'N/A'} (CVSS {v.cvss_score or 'N/A'})\n"
            md += f"- **EPSS score**: {item['epss_score']} | **KEV active**: {item['is_kev']}\n\n"
            md += f"### Executive Summary\n{a['executive_summary']}\n\n"
            md += f"### Technical Analysis\n{a['technical_analysis']}\n\n"
            md += f"### Remediation Action Plan (Priority: {a['patch_priority']})\n{a['recommendations']}\n\n"
            md += "---\n\n"
        return Response(content=md, media_type="text/markdown")
        
    # HTML generation
    elif payload.format.lower() == "html":
        html = """
        <html>
        <head>
            <style>
                body { font-family: 'Helvetica', sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 30px; }
                h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
                .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 25px; }
                .card-header { font-size: 20px; font-weight: bold; color: #f0f6fc; margin-bottom: 10px; border-bottom: 1px dashed #30363d; padding-bottom: 5px; }
                .metric { display: inline-block; background: #21262d; padding: 5px 10px; border-radius: 4px; font-size: 12px; margin-right: 10px; margin-bottom: 15px; }
                .alert-critical { color: #ff7b72; font-weight: bold; }
                h3 { color: #f0f6fc; margin-top: 15px; }
                p { line-height: 1.6; font-size: 14px; color: #8b949e; }
            </style>
        </head>
        <body>
            <h1>AI SOC Threat Intelligence Briefing</h1>
            <p>Generated on: <i>""" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """ UTC</i></p>
        """
        for item in reports_data:
            v = item["vulnerability"]
            a = item["analysis"]
            recs_html = a['recommendations'].replace('\n', '<br>') if a.get('recommendations') else ''
            html += f"""
            <div class="card">
                <div class="card-header">{v.cve_id} - {v.title or 'N/A'}</div>
                <div class="metric">Severity: <span class="alert-critical">{v.severity}</span></div>
                <div class="metric">CVSS Score: <b>{v.cvss_score}</b></div>
                <div class="metric">EPSS Score: <b>{item['epss_score']}</b></div>
                <div class="metric">CISA KEV Active: <b>{'YES' if item['is_kev'] else 'NO'}</b></div>
                
                <h3>Executive Summary</h3>
                <p>{a['executive_summary']}</p>
                
                <h3>Technical Analysis</h3>
                <p>{a['technical_analysis']}</p>
                
                <h3>Remediation Action Plan (Priority: {a['patch_priority']})</h3>
                <p>{recs_html}</p>
            </div>
            """
        html += "</body></html>"
        return Response(content=html, media_type="text/html")
        
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported format. Choose from: pdf, html, markdown"
        )

# Restricted to Admin, Analyst, and Manager roles
manager_analyst_admin_required = Depends(RoleChecker(allowed_roles=["Admin", "Analyst", "Manager"]))

@router.post("/prioritize", dependencies=[manager_analyst_admin_required])
def prioritize_patches(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ranks vulnerabilities by risk score, EPSS, KEV status, and constructs
    a prioritized patch execution order.
    """
    query = db.query(Vulnerability)
    if current_user.organization_id is not None:
        query = query.filter(Vulnerability.organization_id == current_user.organization_id)
    vulns = query.all()
    
    if not vulns:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No vulnerabilities found for this tenant to prioritize."
        )
        
    vulns_list = []
    for v in vulns:
        vulns_list.append({
            "cve_id": v.cve_id,
            "title": v.title,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "is_kev": (v.cisa_kev is not None),
            "epss_score": float(v.epss.score) if v.epss is not None else 0.0,
            "description": v.description
        })
        
    org_name = current_user.organization.name if current_user.organization else "Global System Registry"
    from backend.app.services.ai_service import generate_patch_prioritization
    report = generate_patch_prioritization(org_name, vulns_list)
    
    # Audit trail
    audit = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="PATCH_PRIORITY",
        resource="analysis/prioritize",
        details=f"User '{current_user.username}' ran patch prioritizer with {len(vulns_list)} items."
    )
    db.add(audit)
    db.commit()
    
    return {"report": report}

@router.post("/incident-response/{cve_id}", dependencies=[manager_analyst_admin_required])
def get_incident_response_playbook(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates a localized Incident Response playbook (firewall rules, SIEM queries, patching priority)
    for a specific CVE.
    """
    query = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id)
    if current_user.organization_id is not None:
        query = query.filter(Vulnerability.organization_id == current_user.organization_id)
    vuln = query.first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {cve_id} not found in your organization registry or access is denied."
        )
        
    is_kev = (vuln.cisa_kev is not None)
    epss_score = float(vuln.epss.score) if vuln.epss else 0.0
    cvss_score = float(vuln.cvss_score) if vuln.cvss_score is not None else 0.0
    
    from backend.app.services.ai_service import generate_incident_response_playbook
    playbook = generate_incident_response_playbook(
        cve_id=vuln.cve_id,
        title=vuln.title or "",
        description=vuln.description or "",
        cvss_score=cvss_score,
        cvss_vector=vuln.cvss_vector or "N/A",
        is_kev=is_kev,
        epss_score=epss_score
    )
    
    # Audit trail
    audit = AuditLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="PLAYBOOK_CREATE",
        resource=f"analysis/incident-response/{cve_id}",
        details=f"User '{current_user.username}' created containment playbook for: {cve_id}."
    )
    db.add(audit)
    db.commit()
    
    return {"playbook": playbook}

