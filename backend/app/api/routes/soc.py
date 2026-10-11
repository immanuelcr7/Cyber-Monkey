import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.soc import SocAlert, SocIncident, SocInvestigationNote, SocAuditLog
from app.schemas.soc import (
    SocAlertCreate,
    SocAlertUpdate,
    SocAlertResponse,
    SocIncidentCreate,
    SocIncidentUpdate,
    SocIncidentResponse,
    SocInvestigationNoteCreate,
    SocInvestigationNoteResponse,
    SocAuditLogResponse,
    WazuhStatusResponse,
)
from app.services.wazuh_service import check_wazuh_status, fetch_wazuh_alerts, map_wazuh_level_to_severity

router = APIRouter()

@router.get("/status", response_model=WazuhStatusResponse)
def get_soc_status():
    """Returns Wazuh integration configuration and connection status."""
    return check_wazuh_status()

@router.post("/wazuh/sync")
def sync_wazuh_alerts(db: Session = Depends(get_db)):
    """
    Retrieves real alerts from configured Wazuh manager and ingests them into the SOC database.
    Does not invent fake alerts if Wazuh is not connected.
    """
    status_info = check_wazuh_status()
    if not status_info.get("configured"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Wazuh API is not configured. Configure WAZUH_API_URL, WAZUH_API_USER, and WAZUH_API_PASSWORD in settings."
        )
    if not status_info.get("connected"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Wazuh API is currently unreachable: {status_info.get('message')}"
        )

    success, items, msg = fetch_wazuh_alerts(limit=50)
    if not success:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=msg)

    ingested_count = 0
    for item in items:
        ext_id = str(item.get("id") or item.get("_id") or uuid.uuid4())
        existing = db.query(SocAlert).filter(SocAlert.alert_id == ext_id).first()
        if existing:
            continue

        rule = item.get("rule", {})
        agent = item.get("agent", {})
        rule_level = int(rule.get("level", 5))

        alert = SocAlert(
            alert_id=ext_id,
            rule_id=str(rule.get("id", "0")),
            rule_description=rule.get("description", "Wazuh Security Event"),
            rule_level=rule_level,
            severity=map_wazuh_level_to_severity(rule_level),
            status="new",
            source="Wazuh",
            host_name=agent.get("name"),
            host_ip=agent.get("ip"),
            agent_id=str(agent.get("id", "")),
            raw_data=item,
            evidence=str(item.get("full_log") or rule.get("description"))
        )
        db.add(alert)
        ingested_count += 1

    if ingested_count > 0:
        audit = SocAuditLog(
            action="WAZUH_SYNC",
            performed_by="system",
            target_type="alert",
            target_id="bulk",
            details={"ingested": ingested_count}
        )
        db.add(audit)
        db.commit()

    return {"status": "success", "ingested": ingested_count, "message": f"Successfully synced {ingested_count} new alerts from Wazuh."}

@router.get("/alerts", response_model=List[SocAlertResponse])
def get_alerts(
    severity: Optional[str] = Query(None, description="low, medium, high, critical"),
    status_filter: Optional[str] = Query(None, alias="status", description="new, in_triage, investigating, contained, closed, false_positive"),
    source: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Search in description or host"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists real ingested security alerts with filtering and pagination."""
    query = db.query(SocAlert)
    if severity:
        query = query.filter(SocAlert.severity == severity.lower())
    if status_filter:
        query = query.filter(SocAlert.status == status_filter.lower())
    if source:
        query = query.filter(SocAlert.source == source)
    if q:
        search = f"%{q}%"
        query = query.filter(
            (SocAlert.rule_description.ilike(search)) |
            (SocAlert.host_name.ilike(search)) |
            (SocAlert.host_ip.ilike(search)) |
            (SocAlert.rule_id.ilike(search))
        )
    return query.order_by(desc(SocAlert.timestamp)).offset(offset).limit(limit).all()

@router.post("/alerts", response_model=SocAlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(payload: SocAlertCreate, db: Session = Depends(get_db)):
    """Manually ingests an alert with genuine event telemetry."""
    alert_id = payload.alert_id or f"AL-{uuid.uuid4().hex[:8].upper()}"
    existing = db.query(SocAlert).filter(SocAlert.alert_id == alert_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Alert with this ID already exists.")

    alert = SocAlert(
        alert_id=alert_id,
        rule_id=payload.rule_id,
        rule_description=payload.rule_description,
        rule_level=payload.rule_level,
        severity=payload.severity.lower(),
        status="new",
        source=payload.source,
        host_name=payload.host_name,
        host_ip=payload.host_ip,
        agent_id=payload.agent_id,
        timestamp=payload.timestamp or datetime.utcnow(),
        raw_data=payload.raw_data,
        evidence=payload.evidence
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    audit = SocAuditLog(
        action="ALERT_INGESTED",
        performed_by="analyst",
        target_type="alert",
        target_id=str(alert.id),
        details={"alert_id": alert.alert_id, "rule": alert.rule_id}
    )
    db.add(audit)
    db.commit()

    return alert

@router.get("/alerts/{alert_id}", response_model=SocAlertResponse)
def get_alert_detail(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieves full detail of a specific alert."""
    alert = db.query(SocAlert).filter(SocAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert

@router.patch("/alerts/{alert_id}", response_model=SocAlertResponse)
def update_alert(alert_id: uuid.UUID, payload: SocAlertUpdate, db: Session = Depends(get_db)):
    """Updates status, severity, or incident association for an alert."""
    alert = db.query(SocAlert).filter(SocAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    if payload.status:
        alert.status = payload.status
    if payload.severity:
        alert.severity = payload.severity
    if payload.incident_id is not None:
        alert.incident_id = payload.incident_id

    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    audit = SocAuditLog(
        action="ALERT_UPDATED",
        performed_by="analyst",
        target_type="alert",
        target_id=str(alert.id),
        details={"status": alert.status, "severity": alert.severity}
    )
    db.add(audit)
    db.commit()

    return alert

@router.post("/alerts/{alert_id}/notes", response_model=SocInvestigationNoteResponse)
def add_alert_note(alert_id: uuid.UUID, payload: SocInvestigationNoteCreate, db: Session = Depends(get_db)):
    """Adds investigation note to an alert."""
    alert = db.query(SocAlert).filter(SocAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    note = SocInvestigationNote(
        alert_id=alert.id,
        author=payload.author or "SOC Analyst",
        note=payload.note
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

# Incident Management Endpoints

@router.get("/incidents", response_model=List[SocIncidentResponse])
def get_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists security incidents with associated alerts."""
    query = db.query(SocIncident)
    if status_filter:
        query = query.filter(SocIncident.status == status_filter.lower())
    if severity:
        query = query.filter(SocIncident.severity == severity.lower())
    return query.order_by(desc(SocIncident.created_at)).all()

@router.post("/incidents", response_model=SocIncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(payload: SocIncidentCreate, db: Session = Depends(get_db)):
    """Creates a new tracked incident and associates selected alerts."""
    year = datetime.utcnow().year
    count = db.query(SocIncident).count() + 1
    incident_number = f"INC-{year}-{count:04d}"

    incident = SocIncident(
        incident_number=incident_number,
        title=payload.title,
        description=payload.description,
        severity=payload.severity.lower(),
        status="open",
        assigned_to=payload.assigned_to,
        category=payload.category
    )
    db.add(incident)
    db.flush()

    if payload.alert_ids:
        for a_id in payload.alert_ids:
            alert = db.query(SocAlert).filter(SocAlert.id == a_id).first()
            if alert:
                alert.incident_id = incident.id
                alert.status = "investigating"

    audit = SocAuditLog(
        action="INCIDENT_CREATED",
        performed_by=payload.assigned_to or "analyst",
        target_type="incident",
        target_id=str(incident.id),
        details={"incident_number": incident.incident_number, "title": incident.title}
    )
    db.add(audit)
    db.commit()
    db.refresh(incident)
    return incident

@router.get("/incidents/{incident_id}", response_model=SocIncidentResponse)
def get_incident_detail(incident_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieves full details of an incident including linked alerts."""
    incident = db.query(SocIncident).filter(SocIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident

@router.patch("/incidents/{incident_id}", response_model=SocIncidentResponse)
def update_incident(incident_id: uuid.UUID, payload: SocIncidentUpdate, db: Session = Depends(get_db)):
    """Updates incident status, severity, assignment, or description."""
    incident = db.query(SocIncident).filter(SocIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if payload.title:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity:
        incident.severity = payload.severity
    if payload.status:
        incident.status = payload.status
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
    if payload.category:
        incident.category = payload.category

    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(incident)

    audit = SocAuditLog(
        action="INCIDENT_UPDATED",
        performed_by="analyst",
        target_type="incident",
        target_id=str(incident.id),
        details={"status": incident.status, "assigned_to": incident.assigned_to}
    )
    db.add(audit)
    db.commit()

    return incident

@router.post("/incidents/{incident_id}/notes", response_model=SocInvestigationNoteResponse)
def add_incident_note(incident_id: uuid.UUID, payload: SocInvestigationNoteCreate, db: Session = Depends(get_db)):
    """Adds investigation note to an incident."""
    incident = db.query(SocIncident).filter(SocIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    note = SocInvestigationNote(
        incident_id=incident.id,
        author=payload.author or "SOC Analyst",
        note=payload.note
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@router.get("/audit-logs", response_model=List[SocAuditLogResponse])
def get_soc_audit_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves analyst activity history and compliance audit trail."""
    return db.query(SocAuditLog).order_by(desc(SocAuditLog.created_at)).limit(limit).all()
