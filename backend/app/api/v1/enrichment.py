from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.api.deps import get_current_user, RoleChecker
from backend.app.models.user import User
from backend.app.models.audit_log import AuditLog
from backend.app.services.threat_enrichment import threat_enricher

router = APIRouter()

# Restrict IOC analysis searches to Security Analysts and Administrators
analyst_or_admin_required = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))

class IOCRequest(BaseModel):
    type: str # 'ip', 'hash', 'domain', 'url'
    query: str

@router.post("", dependencies=[analyst_or_admin_required])
def enrich_threat_indicator(
    payload: IOCRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Query multi-source Threat Intelligence feeds for reputational analytics
    on File Hashes, IP addresses, Domains, and URLs.
    """
    ioc_type = payload.type.strip().lower()
    indicator = payload.query.strip()
    
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lookup target indicator query string cannot be empty."
        )
        
    try:
        # Audit Log Entry
        audit = AuditLog(
            user_id=current_user.id,
            action="IOC_ENRICH",
            resource=f"enrich/{ioc_type}",
            details=f"User '{current_user.username}' queried IOC reputation for: {indicator[:50]}"
        )
        db.add(audit)
        db.commit()
        
        # Route depending on type
        if ioc_type == "ip":
            return threat_enricher.enrich_ip(indicator)
        elif ioc_type == "hash":
            return threat_enricher.enrich_hash(indicator)
        elif ioc_type == "domain":
            return threat_enricher.enrich_domain(indicator)
        elif ioc_type == "url":
            return threat_enricher.enrich_url(indicator)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported IOC type '{payload.type}'. Choose from: ip, hash, domain, url."
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat intelligence lookup crashed: {str(e)}"
        )
