from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), unique=True, nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    executive_summary = Column(String, nullable=False)
    technical_analysis = Column(String, nullable=False)
    risk_impact = Column(String, nullable=False)
    recommendations = Column(String, nullable=False)
    patch_priority = Column(String(15), nullable=False) # 'IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW'
    generated_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="ai_analysis")
    organization = relationship("Organization", back_populates="reports")
    user = relationship("User")
