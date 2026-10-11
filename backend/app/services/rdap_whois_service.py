import re
import requests
from typing import Dict, Any, Tuple
from datetime import datetime

def is_ip_address(val: str) -> bool:
    v = val.strip().split(":")[0]
    parts = v.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def sanitize_target(target: str) -> str:
    target = re.sub(r"^https?://", "", target.strip())
    target = target.split("/")[0]
    return target

def execute_rdap_whois_lookup(target: str) -> Dict[str, Any]:
    """
    Performs real public RDAP / WHOIS lookup via official RDAP RFC 7480 protocols.
    Works for both domains and IPv4/IPv6 addresses.
    """
    clean_target = sanitize_target(target)
    is_ip = is_ip_address(clean_target)
    
    endpoint_type = "ip" if is_ip else "domain"
    url = f"https://rdap.org/{endpoint_type}/{clean_target}"

    try:
        resp = requests.get(
            url,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=8.0
        )
        if resp.status_code == 404:
            return {
                "success": False,
                "target": clean_target,
                "target_type": endpoint_type,
                "error": f"Target '{clean_target}' not found in public RDAP registry."
            }
        elif resp.status_code != 200:
            return {
                "success": False,
                "target": clean_target,
                "target_type": endpoint_type,
                "error": f"RDAP lookup returned HTTP {resp.status_code}."
            }

        data = resp.json()
        
        # Parse standard RDAP fields
        events = data.get("events", [])
        creation_date = None
        expiration_date = None
        last_changed = None
        for ev in events:
            action = ev.get("eventAction")
            date_val = ev.get("eventDate")
            if action in ["registration", "created"]:
                creation_date = date_val
            elif action in ["expiration"]:
                expiration_date = date_val
            elif action in ["last changed", "last update"]:
                last_changed = date_val

        # Nameservers
        nameservers = []
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName") or ns.get("handle")
            if ns_name:
                nameservers.append(ns_name)

        # Entities / Registrar
        registrar = None
        entities = []
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            handle = entity.get("handle") or ""
            # VCard parsing
            vcard = entity.get("vcardArray", [])
            fn = None
            if len(vcard) > 1:
                for prop in vcard[1]:
                    if len(prop) > 3 and prop[0] == "fn":
                        fn = prop[3]
            
            entity_label = fn or handle or "Entity"
            if "registrar" in roles:
                registrar = entity_label
            entities.append({
                "roles": roles,
                "name": entity_label,
                "handle": handle
            })

        # Network / IP specific
        network_name = data.get("name")
        start_address = data.get("startAddress")
        end_address = data.get("endAddress")
        ip_version = data.get("ipVersion")

        return {
            "success": True,
            "target": clean_target,
            "target_type": endpoint_type,
            "handle": data.get("handle"),
            "ldh_name": data.get("ldhName"),
            "status": data.get("status", []),
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "last_changed": last_changed,
            "registrar": registrar,
            "nameservers": nameservers,
            "entities": entities[:10],
            "network_name": network_name,
            "ip_range": f"{start_address} - {end_address}" if start_address and end_address else None,
            "ip_version": ip_version,
            "source_url": url,
            "timestamp": datetime.utcnow().isoformat()
        }
    except requests.RequestException as e:
        return {
            "success": False,
            "target": clean_target,
            "target_type": endpoint_type,
            "error": f"RDAP network query failed: {str(e)}"
        }
