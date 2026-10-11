from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.audit import SharedAuditLog
from app.schemas.ai import AiStatusResponse, AiAnalyzeRequest, AiAnalyzeResponse
from app.services.ai_service import get_ai_status, generate_grounded_analysis

router = APIRouter()

@router.get("/status", response_model=AiStatusResponse)
def get_assistant_status():
    """Returns AI Provider configuration and status."""
    return get_ai_status()

@router.post("/analyze", response_model=AiAnalyzeResponse)
def analyze_cyber_evidence(payload: AiAnalyzeRequest, db: Session = Depends(get_db)):
    """
    Produces grounded cybersecurity explanation, inferences, and mitigation recommendations.
    Accepts evidence context from SOC alerts, OSINT, Malware triage, Forensics, or Network monitoring.
    Never fabricates false evidence or undetected threats.
    """
    if not payload.evidence:
        raise HTTPException(status_code=400, detail="Evidence context dictionary is required for analysis.")

    result = generate_grounded_analysis(
        workspace=payload.workspace,
        task_type=payload.task_type,
        evidence=payload.evidence,
        user_query=payload.user_query
    )

    # Record shared audit log
    audit = SharedAuditLog(
        workspace="ai",
        action="AI_ANALYSIS_REQUEST",
        user="analyst",
        details={
            "target_workspace": payload.workspace,
            "task_type": payload.task_type,
            "provider": result.get("provider_used")
        }
    )
    db.add(audit)
    db.commit()

    return result
