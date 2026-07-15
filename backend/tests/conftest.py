import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock
from typing import Generator

from backend.app.database.base import Base
from backend.app.database.session import get_db
from backend.app.main import app
from backend.app.core.security import get_password_hash
from backend.app.models.user import User
from backend.app.models.vendor import Vendor
from backend.app.models.product import Product

# Create SQLite In-Memory database for testing
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def init_db():
    """
    Creates tables inside in-memory testing DB.
    """
    Base.metadata.create_all(bind=engine)
    
    # Pre-seed users for auth testing
    db = TestingSessionLocal()
    try:
        admin = User(
            username="testadmin",
            email="admin@test.local",
            hashed_password=get_password_hash("testpass"),
            role="Admin",
            is_active=True
        )
        analyst = User(
            username="testanalyst",
            email="analyst@test.local",
            hashed_password=get_password_hash("testpass"),
            role="Analyst",
            is_active=True
        )
        viewer = User(
            username="testviewer",
            email="viewer@test.local",
            hashed_password=get_password_hash("testpass"),
            role="Viewer",
            is_active=True
        )
        db.add_all([admin, analyst, viewer])
        
        # Seed simple vendor
        vendor = Vendor(id=1, name="Microsoft")
        product = Product(id=1, vendor_id=1, name="Windows")
        db.add_all([vendor, product])
        db.commit()
    finally:
        db.close()
        
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db() -> Generator:
    """
    Function-scoped database transaction fixture.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(db) -> Generator:
    """
    FastAPI TestClient fixture with overridden DB dependency.
    """
    def override_get_db():
        try:
            yield db
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture(scope="function", autouse=True)
def mock_gemini():
    """
    Mocks Gemini content generation client queries globally.
    """
    with patch("google.generativeai.GenerativeModel") as mock_model:
        instance = mock_model.return_value
        instance.generate_content.return_value = MagicMock(text="""{
            "executive_summary": "Test Executive Summary",
            "technical_analysis": "Test Technical details",
            "risk_impact": "High risk",
            "recommendations": "Apply test patch",
            "patch_priority": "IMMEDIATE"
        }""")
        yield mock_model
