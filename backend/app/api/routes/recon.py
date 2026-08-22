from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID
from datetime import datetime

from app.database.session import get_db
from app.models.assessment import Assessment
from app.models.target import Target
from app.models.recon import (
    NmapScan, NmapPort, SubfinderScan, Subdomain, DnsScan, DnsRecord,
    TheHarvesterScan, TheHarvesterEmail, TheHarvesterHost, TheHarvesterIp, TheHarvesterName
)
from app.schemas.recon import (
    NmapScanCreate, 
    NmapScanResponse, 
    NmapStatusResponse,
    SubfinderScanCreate,
    SubfinderScanResponse,
    SubfinderStatusResponse,
    DnsScanCreate,
    DnsScanResponse,
    DnsStatusResponse,
    TheHarvesterScanCreate,
    TheHarvesterScanResponse,
    TheHarvesterStatusResponse
)
from app.services.nmap_service import check_nmap_availability, execute_nmap_scan
from app.services.subfinder_service import (
    check_subfinder_availability as check_sub_availability,
    execute_subfinder_scan
)
from app.services.dns_service import check_dns_availability, execute_dns_scan
from app.services.theharvester_service import (
    check_theharvester_availability,
    execute_theharvester_scan
)
from app.utils.target_validation import validate_domain, validate_ip, validate_url
from app.services.authorization import is_target_authorized

router = APIRouter()

@router.get("/recon/nmap/status", response_model=NmapStatusResponse)
def get_nmap_status():
    """
    Checks if Nmap is installed on the backend machine.
    """
    installed, version = check_nmap_availability()
    return NmapStatusResponse(installed=installed, version=version)

@router.post("/assessments/{assessment_id}/recon/nmap", response_model=NmapScanResponse)
def run_nmap_scan(
    assessment_id: UUID,
    payload: NmapScanCreate,
    db: Session = Depends(get_db)
):
    """
    Executes a predefined Nmap scan profile against an authorized target.
    """
    # 1. Load and verify assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    # 2. Load and verify target exists
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # 3. Verify target belongs to the assessment
    if target.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested assessment"
        )

    # 4. Verify scope status
    if target.scope_status != "in_scope":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is out of scope"
        )

    # 5. Verify authorization confirmed
    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is not authorized for scanning"
        )

    # 6. Validate scan profile
    valid_profiles = {"host_discovery", "basic_port", "service_detection", "comprehensive"}
    if payload.scan_profile not in valid_profiles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan profile"
        )

    # 7. Check Nmap presence
    installed, _ = check_nmap_availability()
    if not installed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nmap is not installed on the backend."
        )

    # 8. Create scan record (status="running")
    db_scan = NmapScan(
        assessment_id=assessment_id,
        target_id=payload.target_id,
        scan_profile=payload.scan_profile,
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 9. Execute scan
    try:
        scan_result = execute_nmap_scan(target.target_value, payload.scan_profile)
        
        db_scan.status = scan_result["status"]
        db_scan.raw_output = scan_result["raw_output"]
        db_scan.error_output = scan_result["error_output"]
        db_scan.duration = scan_result["duration"]
        db_scan.completed_at = datetime.utcnow()

        if scan_result["status"] == "completed":
            for port_info in scan_result["ports"]:
                db_port = NmapPort(
                    scan_id=db_scan.id,
                    port=port_info["port"],
                    protocol=port_info["protocol"],
                    state=port_info["state"],
                    service=port_info.get("service"),
                    version=port_info.get("version")
                )
                db.add(db_port)
        
        db.commit()
        db.refresh(db_scan)
    except Exception as e:
        db_scan.status = "failed"
        db_scan.error_output = f"Scan execution failed: {str(e)}"
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_scan)

    return db_scan

@router.get("/assessments/{assessment_id}/recon/nmap", response_model=List[NmapScanResponse])
def get_nmap_scan_history(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieves the Nmap scan history for a given assessment.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    scans = db.query(NmapScan).filter(NmapScan.assessment_id == assessment_id).order_by(NmapScan.created_at.desc()).all()
    return scans


@router.get("/recon/subfinder/status", response_model=SubfinderStatusResponse)
def get_subfinder_status():
    """
    Checks if Subfinder is installed on the backend machine.
    """
    installed, version = check_sub_availability()
    return SubfinderStatusResponse(installed=installed, version=version)


@router.post("/assessments/{assessment_id}/recon/subfinder", response_model=SubfinderScanResponse)
def run_subfinder_scan(
    assessment_id: UUID,
    payload: SubfinderScanCreate,
    db: Session = Depends(get_db)
):
    """
    Executes passive subdomain enumeration using Subfinder against an authorized Domain target.
    """
    # 1. Load and verify assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    # 2. Load and verify target exists
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # 3. Verify target belongs to the assessment
    if target.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested assessment"
        )

    # 4. Verify target type == Domain
    if target.target_type != "Domain":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Subfinder scan is only applicable to Domain targets."
        )

    # 5. Verify scope status
    if target.scope_status != "in_scope":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is out of scope"
        )

    # 6. Verify authorization confirmed
    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is not authorized for scanning"
        )

    # 7. Validate target value as a domain syntax
    if not validate_domain(target.target_value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target value is not a valid domain name."
        )

    # 8. Check Subfinder presence
    installed, _ = check_sub_availability()
    if not installed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Subfinder is not installed on the backend."
        )

    # 9. Create scan record (status="running")
    db_scan = SubfinderScan(
        assessment_id=assessment_id,
        target_id=payload.target_id,
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 10. Execute scan
    try:
        scan_result = execute_subfinder_scan(target.target_value)
        
        db_scan.status = scan_result["status"]
        db_scan.raw_output = scan_result["raw_output"]
        db_scan.error_output = scan_result["error_output"]
        db_scan.duration = scan_result["duration"]
        db_scan.completed_at = datetime.utcnow()

        if scan_result["status"] == "completed":
            for subdomain in scan_result["subdomains"]:
                db_sub = Subdomain(
                    scan_id=db_scan.id,
                    subdomain=subdomain
                )
                db.add(db_sub)
        
        db.commit()
        db.refresh(db_scan)
    except Exception as e:
        db_scan.status = "failed"
        db_scan.error_output = f"Scan execution failed: {str(e)}"
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_scan)

    return db_scan


@router.get("/assessments/{assessment_id}/recon/subfinder", response_model=List[SubfinderScanResponse])
def get_subfinder_scan_history(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieves the Subfinder scan history for a given assessment.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    scans = db.query(SubfinderScan).filter(SubfinderScan.assessment_id == assessment_id).order_by(SubfinderScan.created_at.desc()).all()
    return scans


@router.get("/recon/dns/status", response_model=DnsStatusResponse)
def get_dns_status():
    """
    Checks if DNS resolution capability is available on the backend machine.
    """
    available, resolver, detail = check_dns_availability()
    return DnsStatusResponse(available=available, resolver=resolver or f"Unavailable ({detail})")


@router.post("/assessments/{assessment_id}/recon/dns", response_model=DnsScanResponse)
def run_dns_scan(
    assessment_id: UUID,
    payload: DnsScanCreate,
    db: Session = Depends(get_db)
):
    """
    Executes DNS record enumeration against an authorized Domain target.
    """
    # 1. Load and verify assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    # 2. Load and verify target exists
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # 3. Verify target belongs to the assessment
    if target.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested assessment"
        )

    # 4. Verify target type == Domain
    if target.target_type != "Domain":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="DNS enumeration is only applicable to Domain targets."
        )

    # 5. Verify scope status
    if target.scope_status != "in_scope":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is out of scope"
        )

    # 6. Verify authorization confirmed
    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is not authorized for scanning"
        )

    # 7. Reject IP or URL target values
    domain_val = target.target_value
    if validate_ip(domain_val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address targets are not allowed for DNS enumeration."
        )
    if domain_val.startswith(("http://", "https://")) or validate_url(domain_val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL targets are not allowed for DNS enumeration."
        )
    if not validate_domain(domain_val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target value is not a valid domain name."
        )

    # 8. Check DNS availability
    available, _, detail = check_dns_availability()
    if not available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"DNS resolution capability is not available on the backend: {detail}"
        )

    # 9. Create scan record (status="running")
    db_scan = DnsScan(
        assessment_id=assessment_id,
        target_id=payload.target_id,
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 10. Execute scan
    from app.models.recon import DnsRecord
    try:
        scan_result = execute_dns_scan(domain_val)
        
        db_scan.status = scan_result["status"]
        db_scan.error_output = scan_result["error_output"]
        db_scan.duration = scan_result["duration"]
        db_scan.completed_at = datetime.utcnow()

        if scan_result["status"] == "completed":
            for record_info in scan_result["records"]:
                db_record = DnsRecord(
                    scan_id=db_scan.id,
                    record_type=record_info["record_type"],
                    name=record_info["name"],
                    value=record_info["value"],
                    ttl=record_info["ttl"]
                )
                db.add(db_record)
        
        db.commit()
        db.refresh(db_scan)
    except Exception as e:
        db_scan.status = "failed"
        db_scan.error_output = f"DNS resolution failed: {str(e)}"
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_scan)

    return db_scan


@router.get("/assessments/{assessment_id}/recon/dns", response_model=List[DnsScanResponse])
def get_dns_scan_history(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieves the DNS enumeration history for a given assessment.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    scans = db.query(DnsScan).filter(DnsScan.assessment_id == assessment_id).order_by(DnsScan.created_at.desc()).all()
    return scans


@router.get("/recon/theharvester/status", response_model=TheHarvesterStatusResponse)
def get_theharvester_status():
    """
    Checks if theHarvester is installed and available on the backend machine.
    """
    from app.core.config import settings
    installed, version_or_err = check_theharvester_availability()
    return TheHarvesterStatusResponse(
        available=installed,
        path=settings.THEHARVESTER_PATH,
        version=version_or_err if installed else f"Unavailable: {version_or_err}"
    )


@router.post("/assessments/{assessment_id}/recon/theharvester", response_model=TheHarvesterScanResponse)
def run_theharvester_scan(
    assessment_id: UUID,
    payload: TheHarvesterScanCreate,
    db: Session = Depends(get_db)
):
    """
    Executes public OSINT enumeration using theHarvester against an authorized Domain target.
    """
    # 1. Load and verify assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    # 2. Load and verify target exists
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # 3. Verify target belongs to the assessment
    if target.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested assessment"
        )

    # 4. Verify target type == Domain
    if target.target_type != "Domain":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="theHarvester scan is only applicable to Domain targets."
        )

    # 5. Verify scope status
    if target.scope_status != "in_scope":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is out of scope"
        )

    # 6. Verify authorization confirmed
    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is not authorized for scanning"
        )

    # 7. Reject IP or URL target values in validation
    val = target.target_value
    if validate_ip(val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address targets are not allowed for theHarvester scan."
        )
    if val.startswith(("http://", "https://")) or validate_url(val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL targets are not allowed for theHarvester scan."
        )
    if not validate_domain(val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target value is not a valid domain name."
        )

    # 8. Check theHarvester availability
    installed, err_msg = check_theharvester_availability()
    if not installed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"theHarvester is not available on the backend: {err_msg}"
        )

    # 9. Create scan record (status="running")
    db_scan = TheHarvesterScan(
        assessment_id=assessment_id,
        target_id=payload.target_id,
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 10. Execute scan
    try:
        scan_result = execute_theharvester_scan(val)
        
        db_scan.status = scan_result["status"]
        db_scan.raw_output = scan_result["raw_output"]
        db_scan.error_output = scan_result["error_output"]
        db_scan.duration = scan_result["duration"]
        db_scan.return_code = scan_result.get("return_code")
        db_scan.completed_at = datetime.utcnow()
        db_scan.emails_found = len(scan_result["emails"])
        db_scan.hosts_found = len(scan_result["hosts"])
        db_scan.ips_found = len(scan_result["ips"])
        db_scan.names_found = len(scan_result["names"])

        if scan_result["status"] == "completed":
            # Add child findings
            for item in scan_result["emails"]:
                db_email = TheHarvesterEmail(
                    scan_id=db_scan.id,
                    email=item["email"],
                    source=item["source"]
                )
                db.add(db_email)

            for item in scan_result["hosts"]:
                db_host = TheHarvesterHost(
                    scan_id=db_scan.id,
                    hostname=item["hostname"],
                    ip=item["ip"],
                    source=item["source"]
                )
                db.add(db_host)

            for item in scan_result["ips"]:
                db_ip = TheHarvesterIp(
                    scan_id=db_scan.id,
                    ip=item["ip"],
                    source=item["source"]
                )
                db.add(db_ip)

            for item in scan_result["names"]:
                db_name = TheHarvesterName(
                    scan_id=db_scan.id,
                    name=item["name"],
                    source=item["source"]
                )
                db.add(db_name)
        
        db.commit()
        db.refresh(db_scan)
        
        # If the scan itself was marked failed or exited non-zero, raise a sanitized error
        if db_scan.status == "failed" or (db_scan.return_code is not None and db_scan.return_code != 0):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TheHarvester execution failed. Check the scan diagnostics."
            )
            
    except HTTPException:
        # Re-raise HTTPExceptions (like the one we just raised)
        raise
    except Exception as e:
        db_scan.status = "failed"
        db_scan.error_output = f"Scan execution failed: {str(e)}"
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_scan)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TheHarvester execution failed. Check the scan diagnostics."
        )

    return db_scan


@router.get("/assessments/{assessment_id}/recon/theharvester", response_model=List[TheHarvesterScanResponse])
def get_theharvester_scan_history(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieves theHarvester scan history for a given assessment.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )

    scans = db.query(TheHarvesterScan).filter(TheHarvesterScan.assessment_id == assessment_id).order_by(TheHarvesterScan.created_at.desc()).all()
    return scans





# ============================================================
# Shodan Public Intelligence Routes
# ============================================================

from app.models.recon import ShodanScan, ShodanHost, ShodanService, ShodanVulnerability
from app.schemas.recon import (
    ShodanScanCreate, ShodanScanResponse, ShodanStatusResponse
)
from app.services.shodan_service import check_shodan_status, execute_shodan_lookup


@router.get("/recon/shodan/status", response_model=ShodanStatusResponse)
def get_shodan_status():
    """
    Checks whether the Shodan API key is configured and valid.
    Never returns the API key itself.
    """
    return check_shodan_status()


@router.post("/assessments/{assessment_id}/recon/shodan", response_model=ShodanScanResponse)
def run_shodan_scan(
    assessment_id: UUID,
    payload: ShodanScanCreate,
    db: Session = Depends(get_db)
):
    """
    Queries Shodan for public intelligence on an authorized registered target.
    Only target_id is accepted — arbitrary IPs/domains are rejected.
    """
    # 1. Load and verify assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    # 2. Load and verify target exists
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # 3. Verify target belongs to assessment
    if target.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested assessment"
        )

    # 4. Verify in-scope
    if target.scope_status != "in_scope":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target is out of scope")

    # 5. Verify authorization confirmed
    if not target.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is not authorized for scanning"
        )

    # 6. Verify target type is supported
    if target.target_type not in ("IP Address", "Domain"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Shodan lookup is only supported for IP Address or Domain targets."
        )

    # 7. Verify Shodan is configured and available
    shodan_status = check_shodan_status()
    if not shodan_status["configured"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Shodan API key is not configured on the backend."
        )
    if not shodan_status["available"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Shodan API is not available. Check the API key or network connectivity."
        )

    # 8. Create scan record (status="running")
    db_scan = ShodanScan(
        assessment_id=assessment_id,
        target_id=payload.target_id,
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 9. Execute Shodan lookup
    try:
        result = execute_shodan_lookup(target.target_type, target.target_value)

        db_scan.status = result["status"]
        db_scan.duration = result["duration"]
        db_scan.error_output = result["error_output"]
        db_scan.completed_at = datetime.utcnow()

        if result["status"] == "completed":
            for host_data in result["hosts"]:
                db_host = ShodanHost(
                    scan_id=db_scan.id,
                    ip=host_data["ip"],
                    hostname=host_data.get("hostname"),
                    organization=host_data.get("organization"),
                    isp=host_data.get("isp"),
                    country=host_data.get("country"),
                    city=host_data.get("city"),
                    latitude=host_data.get("latitude"),
                    longitude=host_data.get("longitude"),
                    raw_response=host_data.get("raw_response"),
                )
                db.add(db_host)
                db.flush()  # Get db_host.id before adding children

                for svc in host_data.get("services", []):
                    db_service = ShodanService(
                        host_id=db_host.id,
                        port=svc["port"],
                        transport=svc.get("transport"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                        service=svc.get("service"),
                        banner=svc.get("banner"),
                    )
                    db.add(db_service)

                for vuln in host_data.get("vulnerabilities", []):
                    db_vuln = ShodanVulnerability(
                        host_id=db_host.id,
                        cve=vuln["cve"],
                        source=vuln.get("source"),
                        description=vuln.get("description"),
                    )
                    db.add(db_vuln)

        db.commit()
        db.refresh(db_scan)

    except Exception as e:
        db_scan.status = "failed"
        db_scan.error_output = "Shodan lookup failed due to an internal error."
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(db_scan)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Shodan lookup failed. Check the backend logs for details."
        )

    return db_scan


@router.get("/assessments/{assessment_id}/recon/shodan", response_model=List[ShodanScanResponse])
def get_shodan_scan_history(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieves the Shodan scan history for a given assessment.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    scans = (
        db.query(ShodanScan)
        .filter(ShodanScan.assessment_id == assessment_id)
        .order_by(ShodanScan.created_at.desc())
        .all()
    )
    return scans
