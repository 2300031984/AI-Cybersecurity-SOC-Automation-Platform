import os
import sys
import logging
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from backend.app.core.config import settings

class JSONFormatter(logging.Formatter):
    """
    Custom formatter to output logs as single-line JSON objects,
    essential for enterprise log ingestion tools (like ELK/Splunk).
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "file": f"{record.pathname}:{record.lineno}",
            "function": record.funcName
        }
        
        # Include exception traceback if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Add custom attributes if passed via extra
        for key, val in record.__dict__.items():
            if key not in {"args", "asctime", "created", "exc_info", "exc_text", 
                           "filename", "funcName", "levelname", "levelno", "lineno", 
                           "module", "msecs", "message", "msg", "name", "pathname", 
                           "process", "processName", "relativeCreated", "stack_info", 
                           "thread", "threadName"}:
                log_data[key] = val
                
        return json.dumps(log_data)

def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # Ensure logs folder exists
    log_dir = os.path.dirname(settings.LOG_FILE_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # 1. Console Handler (Standard human-readable layout for development)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # 2. File Handler (Enterprise JSON structured layout with rotation)
    file_handler = RotatingFileHandler(
        settings.LOG_FILE_PATH,
        maxBytes=10 * 1024 * 1024, # 10 MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(file_handler)
    
    # Mute loud third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    
    logging.info("Logging infrastructure initialized successfully.")

# Get standard app logger
logger = logging.getLogger("threat_intel")
