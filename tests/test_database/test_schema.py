from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import pytest

from backend.app.models.user import User
from backend.app.models.vendor import Vendor
from backend.app.models.product import Product
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.cisa_kev import CisaKev
from backend.app.models.epss import Epss

def test_create_user(db: Session):
    """
    Test creating a basic user and verifying data is persisted.
    """
    user = User(
        username="newuser",
        email="newuser@example.local",
        hashed_password="somehashvalue",
        role="Viewer",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    assert user.id is not None
    assert user.username == "newuser"
    assert user.role == "Viewer"

def test_vulnerability_vendor_relationship(db: Session):
    """
    Test that vulnerabilities successfully link to vendors and products.
    """
    vendor = Vendor(name="Apache Software")
    db.add(vendor)
    db.commit()
    db.refresh(vendor)
    
    product = Product(vendor_id=vendor.id, name="Log4j")
    db.add(product)
    db.commit()
    db.refresh(product)
    
    vuln = Vulnerability(
        cve_id="CVE-2021-44228",
        title="Log4Shell",
        description="JNDI injection leading to RCE",
        cvss_score=10.0,
        severity="CRITICAL",
        vendor_id=vendor.id,
        product_id=product.id
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    
    assert vuln.vendor.name == "Apache Software"
    assert vuln.product.name == "Log4j"
    assert vuln.severity == "CRITICAL"

def test_cisa_kev_cascade_delete(db: Session):
    """
    Test that deleting a vulnerability cascades down and deletes the KEV entry.
    """
    # Build vulnerability
    v = Vulnerability(
        cve_id="CVE-1111-2222",
        title="Mock Threat",
        description="Desc",
        cvss_score=9.0,
        severity="CRITICAL"
    )
    db.add(v)
    db.commit()
    
    import datetime
    kev = CisaKev(
        cve_id="CVE-1111-2222",
        date_added=datetime.date.today(),
        action_required="Apply patch immediately."
    )
    db.add(kev)
    db.commit()
    
    # Confirm relationship exists
    assert db.query(CisaKev).filter(CisaKev.cve_id == "CVE-1111-2222").first() is not None
    
    # Delete Vulnerability
    db.delete(v)
    db.commit()
    
    # Confirm KEV is cascaded deleted
    assert db.query(CisaKev).filter(CisaKev.cve_id == "CVE-1111-2222").first() is None
