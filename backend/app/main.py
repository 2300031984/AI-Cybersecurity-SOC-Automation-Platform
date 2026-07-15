import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.core.config import settings
from backend.app.core.logging import setup_logging, logger
from backend.app.database.base import Base
from backend.app.database.session import engine, SessionLocal
from backend.app.api.v1 import auth, vulnerabilities, analysis, chat, enrichment, workflow
from backend.app.models.user import User
from backend.app.schemas.ai_analysis import AIAnalysisCreate


# 1. Initialize logging
setup_logging()

# 2. Initialize FastAPI
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Production-grade AI Cybersecurity Threat Intelligence & SOC Automation API",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# 3. Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to Streamlit origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. Startup Database Initialization and Auto-Seeding
@app.on_event("startup")
def startup_db_setup():
    logger.info("Verifying database schema...")
    try:
        # Create tables if they do not exist
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified.")
        
        # Check if database is empty to trigger seeding
        db = SessionLocal()
        try:
            user_count = db.query(User).count()
            if user_count == 0:
                logger.info("Database is empty. Attempting auto-seeding...")
                
                # Search for seed.sql at relative paths
                seed_paths = [
                    "database/seed.sql",
                    "../database/seed.sql",
                    "../../database/seed.sql",
                    "/workspace/database/seed.sql"
                ]
                
                seed_file = None
                for path in seed_paths:
                    if os.path.exists(path):
                        seed_file = path
                        break
                        
                if seed_file:
                    logger.info(f"Loading seed queries from {seed_file}...")
                    with open(seed_file, "r") as f:
                        statements = f.read().split(";")
                        
                    for statement in statements:
                        statement = statement.strip()
                        if statement and not statement.startswith("--"):
                            # Skip SELECT setval statements if using SQLite
                            if "setval" in statement.lower() and engine.dialect.name == "sqlite":
                                continue
                            db.execute(text(statement))
                            
                    db.commit()
                    logger.info("Database successfully seeded with mock threat data.")
                else:
                    logger.warning("seed.sql file not found. Auto-seeding skipped.")
            else:
                logger.info(f"Database contains active data profiles. Active user count: {user_count}.")
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")

# 5. Include API Routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(vulnerabilities.router, prefix=f"{settings.API_V1_STR}", tags=["Vulnerabilities & Statistics"])
app.include_router(analysis.router, prefix=f"{settings.API_V1_STR}", tags=["AI Threat Analysis"])
app.include_router(chat.router, prefix=f"{settings.API_V1_STR}/chat", tags=["AI SOC Chat Assistant"])
app.include_router(enrichment.router, prefix=f"{settings.API_V1_STR}/enrich", tags=["Threat Feeds Ingestion"])
app.include_router(workflow.router, prefix=f"{settings.API_V1_STR}/workflow", tags=["Workflow Execution Logs"])

@app.post("/api/v1/demo/analysis")
def create_demo_analysis(data: AIAnalysisCreate):
    return {
        "id": 1,
        "cve_id": data.cve_id,
        "executive_summary": data.executive_summary,
        "technical_analysis": data.technical_analysis,
        "risk_impact": data.risk_impact,
        "recommendations": data.recommendations,
        "patch_priority": data.patch_priority,
        "demo": True
    }

@app.get("/")
def health_check():
    """
    Standard health check endpoint.
    """
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "database": engine.dialect.name,
        "gemini_api": "connected" if settings.GEMINI_API_KEY else "mock_mode"
    }
