from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class WorkflowExecutionLogCreate(BaseModel):
    workflow_name: str
    execution_id: str
    status: str
    processed_items: int
    failed_node: Optional[str] = None
    error_message: Optional[str] = None

class WorkflowExecutionLogOut(WorkflowExecutionLogCreate):
    id: int
    created_at: datetime

    model_config = {
        "from_attributes": True
    }
