from fastapi import APIRouter
from app.services.wazuh_service import check_wazuh_status
from app.services.shodan_service import check_shodan_status
from app.services.nmap_service import check_nmap_availability
from app.services.subfinder_service import check_subfinder_availability
from app.services.theharvester_service import check_theharvester_availability
from app.services.dns_service import check_dns_availability
from app.services.malware_service import check_yara_status
from app.services.network_monitoring_service import check_network_telemetry_status
from app.services.ai_service import get_ai_status

router = APIRouter()

@router.get("/status")
def get_all_integrations_status():
    """Returns central status and connectivity for all Cyber Monkey tools and engines."""
    wazuh = check_wazuh_status()
    shodan = check_shodan_status()
    nmap_ok, nmap_msg = check_nmap_availability()
    sub_ok, sub_msg = check_subfinder_availability()
    harv_ok, harv_msg = check_theharvester_availability()
    dns_res = check_dns_availability()
    dns_ok = dns_res[0]
    dns_msg = dns_res[2] or dns_res[1] or "DNS resolver active"
    yara_ok, yara_msg = check_yara_status()
    telemetry = check_network_telemetry_status()
    ai = get_ai_status()

    return {
        "wazuh": {
            "name": "wazuh",
            "display_name": "Wazuh SIEM / XDR",
            "is_configured": wazuh.get("configured", False),
            "status": "connected" if wazuh.get("connected") else ("error" if wazuh.get("configured") else "not_configured"),
            "details": {"api_url": wazuh.get("api_url"), "version": wazuh.get("version")},
            "error_message": wazuh.get("message")
        },
        "shodan": {
            "name": "shodan",
            "display_name": "Shodan Internet Intelligence",
            "is_configured": shodan.get("configured", False),
            "status": "connected" if shodan.get("available") else "not_configured",
            "details": shodan,
            "error_message": shodan.get("message")
        },
        "nmap": {
            "name": "nmap",
            "display_name": "Nmap Port & Service Scanner",
            "is_configured": True,
            "status": "connected" if nmap_ok else "error",
            "details": {"available": nmap_ok},
            "error_message": nmap_msg
        },
        "subfinder": {
            "name": "subfinder",
            "display_name": "ProjectDiscovery Subfinder",
            "is_configured": True,
            "status": "connected" if sub_ok else "error",
            "details": {"available": sub_ok},
            "error_message": sub_msg
        },
        "theharvester": {
            "name": "theharvester",
            "display_name": "theHarvester OSINT Engine",
            "is_configured": True,
            "status": "connected" if harv_ok else "error",
            "details": {"available": harv_ok},
            "error_message": harv_msg
        },
        "dns": {
            "name": "dns",
            "display_name": "DNS Resolver Engine",
            "is_configured": True,
            "status": "connected" if dns_ok else "error",
            "details": {"available": dns_ok},
            "error_message": dns_msg
        },
        "yara": {
            "name": "yara",
            "display_name": "YARA Malware Pattern Scanner",
            "is_configured": yara_ok,
            "status": "connected" if yara_ok else "not_configured",
            "details": {"installed": yara_ok},
            "error_message": yara_msg
        },
        "zeek": telemetry["zeek"],
        "suricata": telemetry["suricata"],
        "ai_assistant": {
            "name": "ai_assistant",
            "display_name": "Cyber Monkey AI Assistant",
            "is_configured": ai.get("configured", False),
            "status": "connected" if ai.get("configured") else "not_configured",
            "details": {"provider": ai.get("provider"), "model": ai.get("model")},
            "error_message": ai.get("message")
        }
    }
