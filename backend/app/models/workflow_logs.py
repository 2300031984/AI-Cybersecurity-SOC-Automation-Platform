from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from backend.app.database.session import Base

class WorkflowLog(Base):
    __tablename__ = "workflow_logs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    source = Column(String(100), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False) # 'SUCCESS', 'FAILED'
    details = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class WorkflowExecutionLog(Base):
    __tablename__ = "workflow_execution_logs"

    id = Column(Integer, primary_key=True, index=True)
    workflow_name = Column(String(255), nullable=True)
    execution_id = Column(String(255), nullable=True)
    status = Column(String(50), nullable=True)
    processed_items = Column(Integer, nullable=True)
    failed_node = Column(String(255), nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=False), server_default=func.now())
