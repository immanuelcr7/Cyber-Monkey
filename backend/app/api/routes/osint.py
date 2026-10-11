import uuid
import re
import ipaddress
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.osint import OsintInvestigation, OsintRecord, OsintNote
from app.schemas.osint import (
    OsintInvestigationCreate,
    OsintInvestigationUpdate,
    OsintInvestigationResponse,
    OsintNoteCreate,
    OsintNoteResponse,
    OsintRecordResponse,
    OsintScanActionRequest,
)

# Reuse existing reconnaissance services
from app.services.subfinder_service import check_subfinder_availability, execute_subfinder_scan
from app.services.dns_service import check_dns_availability, execute_dns_scan
from app.services.theharvester_service import check_theharvester_availability, execute_theharvester_scan
from app.services.shodan_service import check_shodan_status, execute_shodan_lookup
from app.services.rdap_whois_service import execute_rdap_whois_lookup

router = APIRouter()

def is_ip_or_cidr(val: str) -> bool:
    val = val.strip()
    try:
        if "/" in val:
            ipaddress.ip_network(val, strict=False)
            return True
        else:
            ipaddress.ip_address(val)
            return True
    except ValueError:
        return False

def is_private_ip(val: str) -> bool:
    val = val.strip()
    try:
        if "/" in val:
            net = ipaddress.ip_network(val, strict=False)
            return net.is_private or net.is_loopback or net.is_reserved
        else:
            ip = ipaddress.ip_address(val)
            return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False

def clean_target_domain(val: str) -> str:
    cleaned = re.sub(r"^https?://", "", val.strip())
    cleaned = cleaned.split("/")[0].split(":")[0]
    return cleaned.lower()

def is_valid_domain(val: str) -> bool:
    domain_clean = clean_target_domain(val)
    if is_ip_or_cidr(domain_clean):
        return False
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_regex, domain_clean))

# Backward-compatibility alias
def is_ip(val: str) -> bool:
    return is_ip_or_cidr(val)

@router.get("/tools/status")
def get_osint_tools_status():
    """Returns availability of shared OSINT tools."""
    sub_ok, sub_msg = check_subfinder_availability()
    dns_res = check_dns_availability()
    dns_ok = dns_res[0]
    dns_msg = dns_res[2] or dns_res[1] or "DNS resolver active"
    harv_ok, harv_msg = check_theharvester_availability()
    shodan_info = check_shodan_status()

    return {
        "subfinder": {"available": sub_ok, "message": sub_msg or "Subfinder active"},
        "dns": {"available": dns_ok, "message": dns_msg or "DNS resolver active"},
        "theharvester": {"available": harv_ok, "message": harv_msg or "theHarvester active"},
        "shodan": {
            "available": shodan_info.get("available", False),
            "configured": shodan_info.get("configured", False),
            "message": shodan_info.get("message", "Shodan API configured")
        },
        "whois_rdap": {"available": True, "message": "ICANN RDAP / WHOIS client active"}
    }

@router.get("/investigations", response_model=List[OsintInvestigationResponse])
def get_investigations(
    status_filter: Optional[str] = Query(None, alias="status"),
    q: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists OSINT investigations with records count."""
    query = db.query(OsintInvestigation)
    if status_filter:
        query = query.filter(OsintInvestigation.status == status_filter.lower())
    if q:
        search = f"%{q}%"
        query = query.filter(
            (OsintInvestigation.title.ilike(search)) |
            (OsintInvestigation.target.ilike(search)) |
            (OsintInvestigation.investigation_purpose.ilike(search))
        )
    investigations = query.order_by(desc(OsintInvestigation.created_at)).all()
    # Populate records_count
    for inv in investigations:
        inv.records_count = len(inv.records)
    return investigations

@router.post("/investigations", response_model=OsintInvestigationResponse, status_code=status.HTTP_201_CREATED)
def create_investigation(payload: OsintInvestigationCreate, db: Session = Depends(get_db)):
    """Creates a new authorized OSINT investigation."""
    title_clean = payload.title.strip()
    if not title_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Investigation title cannot be empty."
        )

    purpose_clean = payload.investigation_purpose.strip()
    if len(purpose_clean) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A legitimate investigation purpose must be specified (at least 3 characters)."
        )

    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization must be explicitly confirmed for authorized OSINT activities."
        )

    raw_target = payload.target.strip()
    if not raw_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target cannot be empty."
        )

    target_type = payload.target_type.lower()
    if target_type == "ip":
        # Validate IPv4/IPv6 or CIDR subnet
        if not is_ip_or_cidr(raw_target):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR subnet: '{raw_target}'. Please provide a valid IP (e.g., 192.168.1.40) or subnet (e.g., 10.0.0.0/24)."
            )
        cleaned_target = raw_target
    elif target_type == "domain":
        cleaned_domain = clean_target_domain(raw_target)
        if is_ip_or_cidr(cleaned_domain):
            # Auto-detect IP if user selected domain but entered an IP
            target_type = "ip"
            cleaned_target = cleaned_domain
        elif not is_valid_domain(cleaned_domain):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain format: '{raw_target}'. Please provide a valid domain name (e.g., example.com)."
            )
        else:
            cleaned_target = cleaned_domain
    elif target_type == "organization":
        if len(raw_target) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization name must be at least 2 characters."
            )
        cleaned_target = raw_target
    else:
        # Fallback target type
        cleaned_target = raw_target

    inv = OsintInvestigation(
        title=title_clean,
        target=cleaned_target,
        target_type=target_type,
        scope_description=payload.scope_description.strip() if payload.scope_description else None,
        investigation_purpose=purpose_clean,
        authorization_confirmed=payload.authorization_confirmed,
        status="active"
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    inv.records_count = 0
    return inv

@router.get("/investigations/{inv_id}", response_model=OsintInvestigationResponse)
def get_investigation_detail(inv_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieves full details, collected intelligence records, and notes for an investigation."""
    inv = db.query(OsintInvestigation).filter(OsintInvestigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    inv.records_count = len(inv.records)
    return inv

@router.patch("/investigations/{inv_id}", response_model=OsintInvestigationResponse)
def update_investigation(inv_id: uuid.UUID, payload: OsintInvestigationUpdate, db: Session = Depends(get_db)):
    """Updates investigation status or scope metadata."""
    inv = db.query(OsintInvestigation).filter(OsintInvestigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    if payload.title:
        inv.title = payload.title
    if payload.scope_description is not None:
        inv.scope_description = payload.scope_description
    if payload.investigation_purpose:
        inv.investigation_purpose = payload.investigation_purpose
    if payload.status:
        inv.status = payload.status

    inv.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inv)
    inv.records_count = len(inv.records)
    return inv

@router.post("/investigations/{inv_id}/notes", response_model=OsintNoteResponse)
def add_investigation_note(inv_id: uuid.UUID, payload: OsintNoteCreate, db: Session = Depends(get_db)):
    """Adds an analyst note to an investigation."""
    inv = db.query(OsintInvestigation).filter(OsintInvestigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    note = OsintNote(
        investigation_id=inv.id,
        author=payload.author or "OSINT Researcher",
        note=payload.note
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@router.post("/investigations/{inv_id}/scan")
def run_investigation_recon(
    inv_id: uuid.UUID,
    payload: OsintScanActionRequest,
    db: Session = Depends(get_db)
):
    """
    Executes an OSINT collection tool against the investigation target.
    Reuses existing Subfinder, DNS, theHarvester, Shodan, and RDAP/WHOIS services.
    Saves intelligence records with source details and collection timestamp.
    """
    inv = db.query(OsintInvestigation).filter(OsintInvestigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    if not payload.authorization_confirmed and not inv.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation required before executing active OSINT collection."
        )

    tool_lower = payload.tool.lower().strip()
    target_val = inv.target

    if tool_lower == "whois_rdap" or tool_lower == "whois":
        if is_private_ip(target_val):
            res = {
                "success": True,
                "target": target_val,
                "target_type": "ip",
                "is_private": True,
                "rfc_standard": "RFC 1918 / IANA Private Address Space",
                "network_name": "Private-Use Networks (Not Publicly Routable)",
                "description": (
                    f"Target IP '{target_val}' belongs to an IANA private address range (RFC 1918). "
                    "Private IP blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 127.0.0.0/8) "
                    "are reserved for internal organizational infrastructure and are not registered with public "
                    "Regional Internet Registries (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC)."
                ),
                "recommendation": (
                    "Public internet OSINT registries cannot provide external intelligence for private IP addresses. "
                    "To investigate or monitor internal network assets, use the Cyber Monkey Network Monitoring "
                    "or Penetration Testing workspaces."
                ),
                "entities": [{"name": "Internet Assigned Numbers Authority (IANA)", "roles": ["reserved"]}],
                "source_url": "https://www.iana.org/assignments/iana-ipv4-special-registry/"
            }
            record = OsintRecord(
                investigation_id=inv.id,
                tool="whois_rdap",
                record_type="rfc1918_private_ip",
                data=res,
                source_url=res.get("source_url"),
                collection_timestamp=datetime.utcnow(),
                is_live=True
            )
            db.add(record)
            db.commit()
            return {"status": "success", "tool": "whois_rdap", "record_id": str(record.id), "result": res}

        res = execute_rdap_whois_lookup(target_val)
        if not res.get("success"):
            raise HTTPException(status_code=502, detail=res.get("error", "RDAP/WHOIS query failed."))
        
        record = OsintRecord(
            investigation_id=inv.id,
            tool="whois_rdap",
            record_type="whois",
            data=res,
            source_url=res.get("source_url"),
            collection_timestamp=datetime.utcnow(),
            is_live=True
        )
        db.add(record)
        db.commit()
        return {"status": "success", "tool": "whois_rdap", "record_id": str(record.id), "result": res}

    elif tool_lower == "subfinder":
        if is_ip_or_cidr(target_val):
            raise HTTPException(status_code=400, detail="Subfinder requires a domain target (e.g. example.com).")
        installed, err_msg = check_subfinder_availability()
        if not installed:
            raise HTTPException(status_code=503, detail=f"Subfinder unavailable: {err_msg}")
        
        res = execute_subfinder_scan(domain=target_val)
        record = OsintRecord(
            investigation_id=inv.id,
            tool="subfinder",
            record_type="subdomain",
            data=res,
            source_url=f"subfinder://{target_val}",
            collection_timestamp=datetime.utcnow(),
            is_live=True
        )
        db.add(record)
        db.commit()
        return {"status": "success", "tool": "subfinder", "record_id": str(record.id), "result": res}

    elif tool_lower == "dns":
        if is_ip_or_cidr(target_val):
            raise HTTPException(status_code=400, detail="DNS lookup requires a domain target (e.g. example.com).")
        available, err_msg = check_dns_availability()
        if not available:
            raise HTTPException(status_code=503, detail=f"DNS service unavailable: {err_msg}")
        
        res = execute_dns_scan(domain=target_val)
        record = OsintRecord(
            investigation_id=inv.id,
            tool="dns",
            record_type="dns_record",
            data=res,
            source_url=f"dns://{target_val}",
            collection_timestamp=datetime.utcnow(),
            is_live=True
        )
        db.add(record)
        db.commit()
        return {"status": "success", "tool": "dns", "record_id": str(record.id), "result": res}

    elif tool_lower in ["theharvester", "the_harvester"]:
        if is_ip_or_cidr(target_val):
            raise HTTPException(status_code=400, detail="theHarvester requires a domain target (e.g. example.com).")
        available, err_msg = check_theharvester_availability()
        if not available:
            raise HTTPException(status_code=503, detail=f"theHarvester unavailable: {err_msg}")

        res = execute_theharvester_scan(domain=target_val)
        record = OsintRecord(
            investigation_id=inv.id,
            tool="theharvester",
            record_type="intelligence_harvest",
            data=res,
            source_url=f"theharvester://{target_val}",
            collection_timestamp=datetime.utcnow(),
            is_live=True
        )
        db.add(record)
        db.commit()
        return {"status": "success", "tool": "theharvester", "record_id": str(record.id), "result": res}

    elif tool_lower == "shodan":
        if is_private_ip(target_val):
            raise HTTPException(
                status_code=400,
                detail=f"Target '{target_val}' is a private local IP (RFC 1918). Shodan only indexes publicly accessible internet assets."
            )
        shodan_info = check_shodan_status()
        if not shodan_info.get("configured") or not shodan_info.get("available"):
            raise HTTPException(status_code=503, detail="Shodan API key is not configured or service is unavailable.")

        t_type = "IP Address" if is_ip_or_cidr(target_val) else "Domain"
        res = execute_shodan_lookup(target_type=t_type, target_value=target_val)
        record = OsintRecord(
            investigation_id=inv.id,
            tool="shodan",
            record_type="shodan_host",
            data=res,
            source_url=f"https://www.shodan.io/host/{target_val}",
            collection_timestamp=datetime.utcnow(),
            is_live=True
        )
        db.add(record)
        db.commit()
        return {"status": "success", "tool": "shodan", "record_id": str(record.id), "result": res}

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported OSINT tool: '{payload.tool}'. Supported: whois_rdap, subfinder, dns, theharvester, shodan."
        )

@router.get("/investigations/{inv_id}/export")
def export_investigation(inv_id: uuid.UUID, db: Session = Depends(get_db)):
    """Exports entire investigation evidence and notes as formatted JSON package."""
    inv = db.query(OsintInvestigation).filter(OsintInvestigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    return {
        "investigation_id": str(inv.id),
        "title": inv.title,
        "target": inv.target,
        "target_type": inv.target_type,
        "scope_description": inv.scope_description,
        "investigation_purpose": inv.investigation_purpose,
        "status": inv.status,
        "created_at": inv.created_at.isoformat(),
        "records_count": len(inv.records),
        "records": [
            {
                "tool": r.tool,
                "record_type": r.record_type,
                "data": r.data,
                "source_url": r.source_url,
                "collection_timestamp": r.collection_timestamp.isoformat(),
                "is_live": r.is_live
            }
            for r in inv.records
        ],
        "notes": [
            {
                "author": n.author,
                "note": n.note,
                "created_at": n.created_at.isoformat()
            }
            for n in inv.notes
        ]
    }
