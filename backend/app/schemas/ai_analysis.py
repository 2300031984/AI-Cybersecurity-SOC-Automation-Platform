from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class AIAnalysisCreate(BaseModel):
    cve_id: str
    executive_summary: str
    technical_analysis: str
    risk_impact: str
    recommendations: str
    patch_priority: str # 'IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW'

class ReportRequest(BaseModel):
    cve_ids: List[str]
    format: str = "pdf" # 'pdf', 'html', 'markdown'

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = []

class ChatResponse(BaseModel):
    answer: str
    source_query: Optional[str] = None
    source_data: Optional[List[Dict[str, Any]]] = None
