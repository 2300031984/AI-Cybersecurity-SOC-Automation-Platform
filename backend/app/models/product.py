from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(500), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Constraints
    __table_args__ = (UniqueConstraint("vendor_id", "name", name="uq_vendor_product"),)

    # Relationships
    vendor = relationship("Vendor", back_populates="products")
    vulnerabilities = relationship("Vulnerability", back_populates="product")
