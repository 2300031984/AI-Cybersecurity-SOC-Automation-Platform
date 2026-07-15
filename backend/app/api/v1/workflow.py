from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.models.workflow_logs import WorkflowExecutionLog
from backend.app.schemas.workflow import WorkflowExecutionLogCreate, WorkflowExecutionLogOut

router = APIRouter()

@router.post("/log", response_model=WorkflowExecutionLogOut, status_code=status.HTTP_201_CREATED)
def create_workflow_execution_log(
    payload: WorkflowExecutionLogCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Endpoint to receive and store workflow execution logs.
    """
    try:
        db_log = WorkflowExecutionLog(
            workflow_name=payload.workflow_name,
            execution_id=payload.execution_id,
            status=payload.status,
            processed_items=payload.processed_items,
            failed_node=payload.failed_node,
            error_message=payload.error_message
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save workflow execution log: {str(e)}"
        )
