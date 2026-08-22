import socket
import time
import logging
import shodan
from typing import Tuple, Optional, Dict, Any, List

logger = logging.getLogger(__name__)


def _get_api_key() -> Optional[str]:
    """
    Returns the Shodan API key from the application settings.
    Never exposes the key in logs or responses.
    """
    from app.core.config import settings
    return settings.SHODAN_API_KEY


def check_shodan_status() -> Dict[str, bool]:
    """
    Verifies the Shodan API key is configured and performs a lightweight
    authenticated API call to confirm it is valid.

    Returns:
        {"configured": bool, "available": bool}

    Never returns the API key.
    """
    api_key = _get_api_key()

    if not api_key:
        return {"configured": False, "available": False}

    # Perform a lightweight authenticated check — /api-info only costs 1 query credit
    # and confirms the key is valid without querying any target.
    try:
        api = shodan.Shodan(api_key)
        # This call authenticates and returns account info without querying targets
        api.info()
        return {"configured": True, "available": True}
    except Exception as e:
        err_str = str(e).lower()
        if "invalid api key" in err_str or "access denied" in err_str or "403" in err_str or "401" in err_str:
            logger.warning("[Shodan] API key is configured but rejected by Shodan: %s", str(e))
            return {"configured": True, "available": False}
        # Could be a network error — key exists but API unreachable
        logger.warning("[Shodan] API check failed (network/timeout): %s", str(e))
        return {"configured": True, "available": False}


def resolve_target_to_ips(target_type: str, target_value: str) -> Tuple[List[str], Optional[str]]:
    """
    Given a registered target (type + value), resolve the IP address(es) to query.

    - For 'IP Address' targets: returns the IP directly without any DNS.
    - For 'Domain' targets: resolves to one or more IPs via getaddrinfo.

    Returns:
        (list_of_ips, error_message_or_None)
    """
    if target_type == "IP Address":
        # Already an IP — validate minimal format and return
        ip = target_value.strip()
        if not ip:
            return [], "Target IP address is empty."
        return [ip], None

    elif target_type == "Domain":
        domain = target_value.strip()
        if not domain:
            return [], "Target domain is empty."
        try:
            # getaddrinfo gives all addresses (IPv4 + IPv6) without shell exec
            results = socket.getaddrinfo(domain, None)
            # Extract unique IPs, prefer IPv4 for Shodan lookups
            seen = set()
            ips = []
            for res in results:
                ip = res[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            if not ips:
                return [], f"Domain '{domain}' did not resolve to any IP addresses."
            # Prioritize IPv4, which Shodan covers best
            ipv4 = [ip for ip in ips if ":" not in ip]
            ipv6 = [ip for ip in ips if ":" in ip]
            return (ipv4 + ipv6), None
        except socket.gaierror as e:
            return [], f"Failed to resolve domain '{domain}': {str(e)}"
        except Exception as e:
            return [], f"Unexpected error resolving domain '{domain}': {str(e)}"
    else:
        return [], f"Unsupported target type for Shodan lookup: {target_type}"


def execute_shodan_lookup(target_type: str, target_value: str) -> Dict[str, Any]:
    """
    Performs a Shodan host lookup for an authorized registered target.

    Workflow:
        1. Resolve target value to IP(s)
        2. Query Shodan for each IP
        3. Normalize the response
        4. Return structured data (no API key exposed)

    Returns a dict with:
        status, duration, error_output, hosts (list of host dicts)
    """
    api_key = _get_api_key()

    if not api_key:
        return {
            "status": "failed",
            "duration": 0.0,
            "error_output": "Shodan API key is not configured.",
            "hosts": [],
        }


    start_time = time.time()
    status = "failed"
    error_output = ""
    hosts_data: List[Dict[str, Any]] = []

    try:
        # Step 1 — Resolve target to IPs
        ips, resolution_error = resolve_target_to_ips(target_type, target_value)

        if resolution_error:
            duration = round(time.time() - start_time, 2)
            return {
                "status": "failed",
                "duration": duration,
                "error_output": resolution_error,
                "hosts": [],
            }

        api = shodan.Shodan(api_key)

        # Step 2 — Query Shodan for each resolved IP
        for ip in ips:
            try:
                logger.info("[Shodan] Querying host: %s", ip)
                host_info = api.host(ip)

                # Step 3 — Normalize the response
                normalized = _normalize_host_response(ip, host_info)
                hosts_data.append(normalized)

            except shodan.APIError as api_err:
                err_str = str(api_err)
                if "no information available" in err_str.lower():
                    # Not an error — Shodan simply has no data for this IP
                    logger.info("[Shodan] No information available for IP: %s", ip)
                    hosts_data.append({
                        "ip": ip,
                        "hostname": None,
                        "organization": None,
                        "isp": None,
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                        "raw_response": None,
                        "services": [],
                        "vulnerabilities": [],
                        "no_data": True,
                    })
                elif "invalid api key" in err_str.lower() or "access denied" in err_str.lower():
                    raise shodan.APIError("Invalid API key or access denied.")
                elif "rate limit" in err_str.lower():
                    raise shodan.APIError("Shodan rate limit reached. Please try again later.")
                else:
                    logger.warning("[Shodan] API error for IP %s: %s", ip, err_str)
                    error_output += f"\nShodan error for {ip}: {err_str}"
            except Exception as exc:
                logger.warning("[Shodan] Unexpected error for IP %s: %s", ip, str(exc))
                error_output += f"\nUnexpected error for {ip}: {str(exc)}"

        duration = round(time.time() - start_time, 2)
        status = "completed"

    except shodan.APIError as critical_err:
        duration = round(time.time() - start_time, 2)
        status = "failed"
        # Sanitize — never expose the API key in error messages
        error_output = str(critical_err)
        logger.error("[Shodan] Critical API error: %s", error_output)

    except Exception as unexpected:
        duration = round(time.time() - start_time, 2)
        status = "failed"
        error_output = f"Unexpected error during Shodan lookup: {type(unexpected).__name__}"
        logger.error("[Shodan] Unexpected exception: %s", str(unexpected))

    return {
        "status": status,
        "duration": duration,
        "error_output": error_output.strip() or None,
        "hosts": hosts_data,
    }


def _normalize_host_response(ip: str, host_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a raw Shodan host API response into a structured dict.
    The raw response is stored for evidence/audit — no credentials are present in it.
    """
    # Extract location data
    location = host_info.get("location", {}) or {}
    latitude = location.get("latitude")
    longitude = location.get("longitude")
    country = location.get("country_name")
    city = location.get("city")

    # Primary hostname
    hostnames = host_info.get("hostnames", []) or []
    hostname = hostnames[0] if hostnames else None

    # Services / ports
    services = []
    for item in host_info.get("data", []) or []:
        port = item.get("port")
        transport = item.get("transport", "tcp")
        product = item.get("product")
        version = item.get("version")
        # Module is more descriptive than _shodan.module for service name
        service_name = item.get("_shodan", {}).get("module") or item.get("product") or None
        banner = item.get("data", "")
        # Truncate banners to avoid excessively large DB rows
        if banner and len(banner) > 2000:
            banner = banner[:2000] + "\n[truncated]"

        if port is not None:
            services.append({
                "port": port,
                "transport": transport,
                "product": product,
                "version": version,
                "service": service_name,
                "banner": banner,
            })

    # Vulnerabilities (CVEs) — only what Shodan explicitly reports
    vulns_dict = host_info.get("vulns", {}) or {}
    vulnerabilities = []
    for cve_id, vuln_info in vulns_dict.items():
        description = None
        if isinstance(vuln_info, dict):
            description = vuln_info.get("summary") or vuln_info.get("description")
        vulnerabilities.append({
            "cve": cve_id,
            "source": "shodan",
            "description": description,
        })

    # Build a sanitized raw_response for audit storage
    # Strip any fields that could contain API keys or credentials (none in standard Shodan host response)
    raw_response = {
        "ip_str": host_info.get("ip_str"),
        "hostnames": host_info.get("hostnames", []),
        "org": host_info.get("org"),
        "isp": host_info.get("isp"),
        "asn": host_info.get("asn"),
        "country_name": location.get("country_name"),
        "city": location.get("city"),
        "latitude": latitude,
        "longitude": longitude,
        "ports": host_info.get("ports", []),
        "tags": host_info.get("tags", []),
        "vulns": list(vulns_dict.keys()),
        "last_update": host_info.get("last_update"),
    }

    return {
        "ip": ip,
        "hostname": hostname,
        "organization": host_info.get("org"),
        "isp": host_info.get("isp"),
        "country": country,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
        "raw_response": raw_response,
        "services": services,
        "vulnerabilities": vulnerabilities,
        "no_data": False,
    }
