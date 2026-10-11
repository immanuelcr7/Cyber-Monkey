from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class AiStatusResponse(BaseModel):
    configured: bool
    provider: Optional[str] = None
    model: Optional[str] = None
    message: str

class AiAnalyzeRequest(BaseModel):
    workspace: str = Field(..., description="soc, osint, malware, forensics, network, pentest")
    task_type: str = Field("explain", description="explain, summarize, recommend, triage")
    evidence: Dict[str, Any] = Field(..., description="Structured real evidence to analyze")
    user_query: Optional[str] = None

class AiAnalyzeResponse(BaseModel):
    workspace: str
    task_type: str
    provider_used: str
    summary: str
    evidence_extracted: List[str]
    inferences: List[str]
    recommendations: List[str]
    mitre_techniques: Optional[List[str]] = []
    confidence: str = "high"
