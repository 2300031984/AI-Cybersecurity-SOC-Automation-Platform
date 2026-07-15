import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Cybersecurity Threat Monitor"
    API_V1_STR: str = "/api/v1"
    
    # Database Configuration (Defaults to SQLite for local development/testing)
    DATABASE_URL: str = "sqlite:///./threat_intel.db"
    
    # Security Configuration
    SECRET_KEY: str = "supersecretkey_change_me_in_production_1234567890"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # AI configuration
    GEMINI_API_KEY: Optional[str] = None
    
    # NVD API Key (Optional, for higher rate limits)
    NVD_API_KEY: Optional[str] = None
    
    # Threat enrichment API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FILE_PATH: str = "logs/backend.log"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
