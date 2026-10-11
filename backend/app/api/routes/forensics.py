import os
import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.config import settings
from app.database.session import get_db
from app.models.forensics import ForensicCase, ForensicEvidence, ChainOfCustody, ForensicTimelineEvent, ForensicNote
from app.schemas.forensics import (
    ForensicCaseCreate,
    ForensicCaseUpdate,
    ForensicCaseResponse,
    ForensicEvidenceResponse,
    ChainOfCustodyCreate,
    ChainOfCustodyResponse,
    ForensicTimelineEventCreate,
    ForensicTimelineEventResponse,
    ForensicNoteCreate,
    ForensicNoteResponse,
    VerifyIntegrityResponse,
)
from app.services.forensics_service import (
    ingest_forensic_evidence_file,
    verify_evidence_hash_on_disk,
    export_case_to_json,
    export_timeline_to_csv,
)

router = APIRouter()

def get_forensics_storage_path() -> str:
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    path = os.path.join(base, settings.FORENSICS_STORAGE_PATH)
    os.makedirs(path, exist_ok=True)
    return path

@router.get("/status")
def get_forensics_status():
    """Returns status of forensic evidence storage and acquisition engines."""
    return {
        "engine": "Cryptographic Hash & Chain-of-Custody Verification Engine",
        "hashing_algorithm": "SHA-256 (NIST FIPS 180-4)",
        "evidence_preservation": "Strict Read-Only Immutable Storage",
        "disk_parsing": "Metadata and artifact triage active. Raw disk image parsing requires SleuthKit (Not Configured)."
    }

@router.get("/cases", response_model=List[ForensicCaseResponse])
def get_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists forensic cases with evidence counts."""
    query = db.query(ForensicCase)
    if status_filter:
        query = query.filter(ForensicCase.status == status_filter.lower())
    if priority:
        query = query.filter(ForensicCase.priority == priority.lower())
    if q:
        search = f"%{q}%"
        query = query.filter(
            (ForensicCase.case_number.ilike(search)) |
            (ForensicCase.title.ilike(search)) |
            (ForensicCase.investigator.ilike(search))
        )
    cases = query.order_by(desc(ForensicCase.created_at)).all()
    for c in cases:
        c.evidence_count = len(c.evidence)
    return cases

@router.post("/cases", response_model=ForensicCaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(payload: ForensicCaseCreate, db: Session = Depends(get_db)):
    """Creates a new forensic case."""
    existing = db.query(ForensicCase).filter(ForensicCase.case_number == payload.case_number).first()
    if existing:
        raise HTTPException(status_code=400, detail="Case number already exists.")

    case = ForensicCase(
        case_number=payload.case_number,
        title=payload.title,
        description=payload.description,
        investigator=payload.investigator,
        priority=payload.priority.lower(),
        status="active"
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    case.evidence_count = 0
    return case

@router.get("/cases/{case_id}", response_model=ForensicCaseResponse)
def get_case_detail(case_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieves full case details including evidence items, custody records, and timeline."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    case.evidence_count = len(case.evidence)
    return case

@router.patch("/cases/{case_id}", response_model=ForensicCaseResponse)
def update_case(case_id: uuid.UUID, payload: ForensicCaseUpdate, db: Session = Depends(get_db)):
    """Updates case status, investigator, or priority."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    if payload.title:
        case.title = payload.title
    if payload.description is not None:
        case.description = payload.description
    if payload.investigator:
        case.investigator = payload.investigator
    if payload.priority:
        case.priority = payload.priority
    if payload.status:
        case.status = payload.status

    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    case.evidence_count = len(case.evidence)
    return case

@router.post("/cases/{case_id}/evidence", response_model=ForensicEvidenceResponse, status_code=status.HTTP_201_CREATED)
async def acquire_evidence(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    evidence_identifier: str = Form(...),
    media_type: str = Form("log_file"),
    source_location: str = Form(...),
    collector_name: str = Form(...),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Acquires digital evidence item:
    - Computes acquisition SHA-256 hash.
    - Saves into read-only isolated storage.
    - Automatically creates initial Chain-of-Custody record.
    """
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Evidence file cannot be empty.")

    storage_dir = get_forensics_storage_path()
    storage_id, sha256_hash, file_size = ingest_forensic_evidence_file(
        filename=file.filename,
        file_bytes=content,
        storage_dir=storage_dir
    )

    evidence = ForensicEvidence(
        case_id=case.id,
        evidence_identifier=evidence_identifier,
        original_filename=os.path.basename(file.filename or "unknown_evidence"),
        storage_identifier=storage_id,
        media_type=media_type,
        file_size=file_size,
        source_location=source_location,
        collector_name=collector_name,
        acquisition_timestamp=datetime.utcnow(),
        acquisition_sha256=sha256_hash,
        verification_status="VERIFIED",
        read_only_status=True,
        notes=notes
    )
    db.add(evidence)
    db.flush()

    # Initial Chain of Custody entry
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        action="ACQUISITION",
        performed_by=collector_name,
        location=source_location,
        timestamp=datetime.utcnow(),
        reason="Initial evidentiary acquisition and cryptographic SHA-256 hashing.",
        verified_hash=sha256_hash
    )
    db.add(custody)
    db.commit()
    db.refresh(evidence)
    return evidence

@router.post("/evidence/{evidence_id}/verify-integrity", response_model=VerifyIntegrityResponse)
def verify_evidence_integrity(evidence_id: uuid.UUID, db: Session = Depends(get_db)):
    """
    On-demand cryptographic integrity verification:
    - Re-hashes stored evidence file on disk.
    - Compares computed hash against acquisition hash.
    - Records verification result in Chain of Custody log.
    """
    evidence = db.query(ForensicEvidence).filter(ForensicEvidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found.")

    storage_dir = get_forensics_storage_path()
    res = verify_evidence_hash_on_disk(
        storage_dir=storage_dir,
        storage_identifier=evidence.storage_identifier,
        acquisition_sha256=evidence.acquisition_sha256
    )

    evidence.last_verified_sha256 = res.get("computed_sha256")
    evidence.last_verification_timestamp = res.get("verification_timestamp")
    evidence.verification_status = res.get("status")

    # Record chain of custody event
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        action="INTEGRITY_VERIFICATION",
        performed_by="Forensic Integrity Engine",
        location="Secure Storage",
        timestamp=datetime.utcnow(),
        reason=res.get("message"),
        verified_hash=res.get("computed_sha256")
    )
    db.add(custody)
    db.commit()

    return {
        "evidence_id": evidence.id,
        "status": res["status"],
        "acquisition_sha256": evidence.acquisition_sha256,
        "computed_sha256": res.get("computed_sha256"),
        "matches": res["matches"],
        "verification_timestamp": res["verification_timestamp"],
        "message": res["message"]
    }

@router.post("/evidence/{evidence_id}/custody", response_model=ChainOfCustodyResponse)
def add_chain_of_custody_entry(
    evidence_id: uuid.UUID,
    payload: ChainOfCustodyCreate,
    db: Session = Depends(get_db)
):
    """Logs an evidence custody transfer or analysis event."""
    evidence = db.query(ForensicEvidence).filter(ForensicEvidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found.")

    custody = ChainOfCustody(
        evidence_id=evidence.id,
        action=payload.action,
        performed_by=payload.performed_by,
        location=payload.location,
        reason=payload.reason,
        verified_hash=evidence.acquisition_sha256
    )
    db.add(custody)
    db.commit()
    db.refresh(custody)
    return custody

@router.post("/cases/{case_id}/timeline", response_model=ForensicTimelineEventResponse)
def add_timeline_event(
    case_id: uuid.UUID,
    payload: ForensicTimelineEventCreate,
    db: Session = Depends(get_db)
):
    """Adds a timestamped forensic event to the case timeline."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    event = ForensicTimelineEvent(
        case_id=case.id,
        timestamp=payload.timestamp,
        event_source=payload.event_source,
        source_host=payload.source_host,
        user_account=payload.user_account,
        event_description=payload.event_description,
        severity=payload.severity.lower(),
        evidence_id=payload.evidence_id
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

@router.post("/cases/{case_id}/notes", response_model=ForensicNoteResponse)
def add_case_note(
    case_id: uuid.UUID,
    payload: ForensicNoteCreate,
    db: Session = Depends(get_db)
):
    """Adds an investigator note to a case."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    note = ForensicNote(
        case_id=case.id,
        author=payload.author or "Forensic Investigator",
        content=payload.content
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@router.get("/cases/{case_id}/export/json")
def export_case_json(case_id: uuid.UUID, db: Session = Depends(get_db)):
    """Exports full case, evidence, custody, and timeline to JSON."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    case_dict = {
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "investigator": case.investigator,
        "priority": case.priority,
        "status": case.status,
        "created_at": case.created_at.isoformat(),
        "evidence_items": [
            {
                "identifier": ev.evidence_identifier,
                "filename": ev.original_filename,
                "size_bytes": ev.file_size,
                "media_type": ev.media_type,
                "acquisition_hash": ev.acquisition_sha256,
                "status": ev.verification_status,
                "source": ev.source_location,
                "collector": ev.collector_name,
                "custody_history": [
                    {
                        "action": c.action,
                        "by": c.performed_by,
                        "location": c.location,
                        "timestamp": c.timestamp.isoformat(),
                        "reason": c.reason
                    }
                    for c in ev.chain_of_custody
                ]
            }
            for ev in case.evidence
        ],
        "timeline_events": [
            {
                "timestamp": t.timestamp.isoformat(),
                "source": t.event_source,
                "host": t.source_host,
                "user": t.user_account,
                "severity": t.severity,
                "description": t.event_description
            }
            for t in case.timeline_events
        ]
    }
    json_str = export_case_to_json(case_dict)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={case.case_number}_export.json"}
    )

@router.get("/cases/{case_id}/export/timeline-csv")
def export_case_timeline_csv(case_id: uuid.UUID, db: Session = Depends(get_db)):
    """Exports timeline events as CSV."""
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    events_list = [
        {
            "timestamp": t.timestamp.isoformat(),
            "event_source": t.event_source,
            "source_host": t.source_host,
            "user_account": t.user_account,
            "severity": t.severity,
            "event_description": t.event_description
        }
        for t in case.timeline_events
    ]
    csv_str = export_timeline_to_csv(events_list)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={case.case_number}_timeline.csv"}
    )
