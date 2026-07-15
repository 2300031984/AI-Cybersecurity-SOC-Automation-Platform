from sqlalchemy import Column, String, Date, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

class CisaKev(Base):
    __tablename__ = "cisa_kev"

    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), primary_key=True)
    date_added = Column(Date, nullable=False)
    due_date = Column(Date)
    action_required = Column(String, nullable=False)
    short_description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="cisa_kev")
