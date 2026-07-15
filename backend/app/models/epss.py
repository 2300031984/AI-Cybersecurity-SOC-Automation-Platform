from sqlalchemy import Column, String, Numeric, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

class Epss(Base):
    __tablename__ = "epss"

    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), primary_key=True)
    score = Column(Numeric(6, 5), nullable=False, index=True)
    percentile = Column(Numeric(6, 5), nullable=False)
    retrieved_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="epss")
