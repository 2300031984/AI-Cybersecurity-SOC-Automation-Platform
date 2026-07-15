from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.api.deps import get_current_user, RoleChecker
from backend.app.models.user import User
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.ai_analysis import ChatRequest, ChatResponse
from backend.app.services.ai_service import ask_soc_assistant

from backend.app.rag.copilot import copilot_rag

router = APIRouter()

# Restricted to SOC Analysts and Administrators
analyst_or_admin_required = Depends(RoleChecker(allowed_roles=["Admin", "Analyst"]))

@router.post("", response_model=ChatResponse, dependencies=[analyst_or_admin_required])
def soc_chat_assistant(
    payload: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    SOC Chat Assistant Endpoint (RAG).
    Accepts natural language questions, runs read-only queries against
    the vulnerability tables, and outputs summarized reports.
    """
    try:
        response_dict = copilot_rag.ask(
            db=db,
            question=payload.message,
            organization_id=current_user.organization_id
        )
        
        # Audit Log
        audit = AuditLog(
            user_id=current_user.id,
            organization_id=current_user.organization_id,
            action="CHAT_QUERY",
            resource="chat",
            details=f"User '{current_user.username}' queried SOC Chat: '{payload.message[:60]}...'"
        )
        db.add(audit)
        db.commit()
        
        return ChatResponse(
            answer=response_dict["answer"],
            source_query=response_dict.get("source_query"),
            source_data=response_dict.get("source_data")
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"SOC Assistant crashed during execution: {str(e)}"
        )
