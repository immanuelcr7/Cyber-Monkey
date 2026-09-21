from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Any

from app.services.nmap_service import check_nmap_availability, execute_nmap_scan
from app.services.subfinder_service import check_subfinder_availability, execute_subfinder_scan
from app.services.dns_service import check_dns_availability, execute_dns_scan
from app.services.theharvester_service import check_theharvester_availability, execute_theharvester_scan
from app.services.shodan_service import check_shodan_status, execute_shodan_lookup

from app.services.nuclei_service import check_nuclei_availability, execute_nuclei_scan
from app.services.nikto_service import check_nikto_availability, execute_nikto_scan, sanitize_target_and_port


router = APIRouter()

def is_ip_address(val: str) -> bool:
    v = val.strip().split(":")[0]
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


# Request Schemas for Standalone Mode
class StandaloneReconScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP address")
    tool: str = Field("theHarvester", description="Tool name: theHarvester, subfinder, dns, shodan")
    authorization_confirmed: bool = False

class StandaloneNmapRequest(BaseModel):
    target_value: str
    scan_profile: str = "service_detection"
    authorization_confirmed: bool = False

class StandaloneSubfinderRequest(BaseModel):
    target_value: str
    authorization_confirmed: bool = False

class StandaloneDnsRequest(BaseModel):
    target_value: str
    authorization_confirmed: bool = False

class StandaloneTheHarvesterRequest(BaseModel):
    target_value: str
    authorization_confirmed: bool = False

class StandaloneShodanRequest(BaseModel):
    target_value: str
    authorization_confirmed: bool = False

class StandaloneNucleiRequest(BaseModel):
    target_value: str
    profile: str = "BASIC"
    authorization_confirmed: bool = False

class StandaloneNiktoRequest(BaseModel):
    target_value: str
    port: Optional[int] = 80
    authorization_confirmed: bool = False


# Standalone Unified Reconnaissance Endpoint (Task 2)
@router.post("/reconnaissance/scan")
def run_standalone_recon_scan(payload: StandaloneReconScanRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )

    tool_lower = payload.tool.lower().strip()
    target_clean = payload.target.strip()

    if tool_lower in ["theharvester", "the_harvester"]:
        if is_ip_address(target_clean):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="theHarvester requires a domain target (e.g., example.com)."
            )
        available, err_msg = check_theharvester_availability()

        if not available:
            raise HTTPException(
                status_code=503,
                detail=f"theHarvester is unavailable on backend host: {err_msg}"
            )
        try:
            res = execute_theharvester_scan(domain=target_clean)
            return res
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    elif tool_lower == "subfinder":
        if is_ip_address(target_clean):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Subfinder requires a domain target (e.g., example.com)."
            )
        installed, err_msg = check_subfinder_availability()
        if not installed:
            raise HTTPException(
                status_code=503,
                detail=f"Subfinder is unavailable on backend host: {err_msg}"
            )
        res = execute_subfinder_scan(domain=target_clean)
        return res

    elif tool_lower == "dns":
        if is_ip_address(target_clean):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="DNS lookup requires a domain target (e.g., example.com)."
            )
        available, err_msg = check_dns_availability()
        if not available:
            raise HTTPException(
                status_code=503,
                detail=f"DNS resolver service is unavailable: {err_msg}"
            )
        res = execute_dns_scan(domain=target_clean)
        return res

    elif tool_lower == "shodan":
        status_info = check_shodan_status()
        if not status_info.get("configured") or not status_info.get("available"):
            raise HTTPException(
                status_code=503,
                detail="Shodan API key is not configured or service is unavailable."
            )
        target_type = "IP Address" if is_ip_address(target_clean) else "Domain"
        res = execute_shodan_lookup(target_type=target_type, target_value=target_clean)
        return res

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported reconnaissance tool: '{payload.tool}'."
        )


# Standalone Individual Endpoints (Mode 1: Quick Scan without Assessment creation)

@router.post("/recon/nmap")
def run_standalone_nmap(payload: StandaloneNmapRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    installed, _ = check_nmap_availability()
    if not installed:
        raise HTTPException(
            status_code=503,
            detail="Nmap is not installed or accessible on backend host."
        )
    res = execute_nmap_scan(target_val=payload.target_value, scan_profile=payload.scan_profile)
    return res


@router.post("/recon/subfinder")
def run_standalone_subfinder(payload: StandaloneSubfinderRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    if is_ip_address(payload.target_value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Subfinder requires a domain target (e.g., example.com)."
        )
    installed, _ = check_subfinder_availability()
    if not installed:
        raise HTTPException(
            status_code=503,
            detail="Subfinder is not available on backend host."
        )
    res = execute_subfinder_scan(domain=payload.target_value)
    return res


@router.post("/recon/dns")
def run_standalone_dns(payload: StandaloneDnsRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    if is_ip_address(payload.target_value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="DNS lookup requires a domain target (e.g., example.com)."
        )
    available, _ = check_dns_availability()
    if not available:
        raise HTTPException(
            status_code=503,
            detail="DNS resolver service unavailable."
        )
    res = execute_dns_scan(domain=payload.target_value)
    return res


@router.post("/recon/theharvester")
def run_standalone_theharvester(payload: StandaloneTheHarvesterRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    if is_ip_address(payload.target_value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="theHarvester requires a domain target (e.g., example.com)."
        )
    available, err_msg = check_theharvester_availability()

    if not available:
        raise HTTPException(
            status_code=503,
            detail="theHarvester executable unavailable."
        )
    res = execute_theharvester_scan(domain=payload.target_value)
    return res


@router.post("/recon/shodan")
def run_standalone_shodan(payload: StandaloneShodanRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    status_info = check_shodan_status()
    if not status_info.get("configured") or not status_info.get("available"):
        raise HTTPException(
            status_code=503,
            detail="Shodan API key is not configured or service is unavailable."
        )
    target_type = "IP Address" if is_ip_address(payload.target_value) else "Domain"
    res = execute_shodan_lookup(target_type=target_type, target_value=payload.target_value)
    return res


@router.post("/vulnerabilities/nuclei")
def run_standalone_nuclei(payload: StandaloneNucleiRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    available, _ = check_nuclei_availability()
    if not available:
        raise HTTPException(
            status_code=503,
            detail="Nuclei binary executable is not available on backend host."
        )
    res = execute_nuclei_scan(target_val=payload.target_value, profile=payload.profile)
    return res


@router.post("/vulnerabilities/nikto")
def run_standalone_nikto(payload: StandaloneNiktoRequest):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target authorization must be explicitly confirmed before scanning."
        )
    available, _ = check_nikto_availability()
    if not available:
        raise HTTPException(
            status_code=503,
            detail="Nikto executable or Perl environment is not available on backend host."
        )
    port = payload.port or 80
    if not (1 <= port <= 65535):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid port: {port}. Port must be between 1 and 65535."
        )
    res = execute_nikto_scan(target_val=payload.target_value, port=port)
    return res
