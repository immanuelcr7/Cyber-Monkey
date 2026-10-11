import os
import requests
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from app.core.config import settings

def check_wazuh_status() -> Dict[str, Any]:
    """
    Inspects whether Wazuh integration is configured and tests API reachability.
    Never exposes passwords.
    """
    api_url = settings.WAZUH_API_URL or os.environ.get("WAZUH_API_URL")
    user = settings.WAZUH_API_USER or os.environ.get("WAZUH_API_USER")
    password = settings.WAZUH_API_PASSWORD or os.environ.get("WAZUH_API_PASSWORD")

    if not api_url or not user or not password:
        return {
            "configured": False,
            "connected": False,
            "api_url": api_url or None,
            "version": None,
            "message": "Wazuh API is not configured. Configure WAZUH_API_URL, WAZUH_API_USER, and WAZUH_API_PASSWORD in settings.",
            "last_checked": datetime.utcnow()
        }

    clean_url = api_url.rstrip("/")
    try:
        # Request authentication token from Wazuh API
        auth_url = f"{clean_url}/security/user/authenticate"
        resp = requests.get(
            auth_url,
            auth=(user, password),
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=5.0
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("data", {}).get("token")
            # Fetch manager version
            headers = {"Authorization": f"Bearer {token}"}
            mgr_resp = requests.get(
                f"{clean_url}/manager/info",
                headers=headers,
                verify=settings.WAZUH_VERIFY_SSL,
                timeout=5.0
            )
            version = "Wazuh Manager"
            if mgr_resp.status_code == 200:
                mgr_data = mgr_resp.json()
                version = mgr_data.get("data", {}).get("version", "Wazuh API")

            return {
                "configured": True,
                "connected": True,
                "api_url": clean_url,
                "version": version,
                "message": "Successfully connected to Wazuh API.",
                "last_checked": datetime.utcnow()
            }
        else:
            return {
                "configured": True,
                "connected": False,
                "api_url": clean_url,
                "version": None,
                "message": f"Wazuh authentication failed (HTTP {resp.status_code}): {resp.text[:200]}",
                "last_checked": datetime.utcnow()
            }
    except requests.RequestException as e:
        return {
            "configured": True,
            "connected": False,
            "api_url": clean_url,
            "version": None,
            "message": f"Wazuh API connection failed: {str(e)}",
            "last_checked": datetime.utcnow()
        }

def fetch_wazuh_alerts(limit: int = 50, q: Optional[str] = None) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Fetches real alerts from the Wazuh API.
    Returns (success, alerts_list, message).
    """
    api_url = settings.WAZUH_API_URL or os.environ.get("WAZUH_API_URL")
    user = settings.WAZUH_API_USER or os.environ.get("WAZUH_API_USER")
    password = settings.WAZUH_API_PASSWORD or os.environ.get("WAZUH_API_PASSWORD")

    if not api_url or not user or not password:
        return False, [], "Wazuh credentials not configured."

    clean_url = api_url.rstrip("/")
    try:
        # Authenticate
        resp = requests.get(
            f"{clean_url}/security/user/authenticate",
            auth=(user, password),
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=5.0
        )
        if resp.status_code != 200:
            return False, [], f"Wazuh authentication failed: HTTP {resp.status_code}"

        token = resp.json().get("data", {}).get("token")
        headers = {"Authorization": f"Bearer {token}"}
        
        params = {"limit": limit}
        if q:
            params["q"] = q

        alerts_resp = requests.get(
            f"{clean_url}/alerts",
            headers=headers,
            params=params,
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=10.0
        )

        if alerts_resp.status_code != 200:
            return False, [], f"Failed to retrieve alerts: HTTP {alerts_resp.status_code}"

        alerts_data = alerts_resp.json().get("data", {}).get("items", [])
        return True, alerts_data, "Alerts retrieved successfully."
    except Exception as e:
        return False, [], f"Error connecting to Wazuh alerts endpoint: {str(e)}"

def map_wazuh_level_to_severity(level: int) -> str:
    """
    Maps Wazuh 1-15 rule level to severity string.
    """
    if level >= 12:
        return "critical"
    elif level >= 8:
        return "high"
    elif level >= 4:
        return "medium"
    return "low"
