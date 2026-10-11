import os
import time
import socket
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from app.core.config import settings

def probe_port(ip_address: str, port: int, timeout: float = 1.5) -> Tuple[bool, Optional[float], str]:
    """
    Performs a real TCP socket connection probe against target IP and port.
    Returns: (is_open, response_time_ms, banner_or_error)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.perf_counter()
    try:
        err = s.connect_ex((ip_address, port))
        elapsed = (time.perf_counter() - start) * 1000.0  # ms
        if err == 0:
            # Optionally grab a short banner if available
            banner = ""
            try:
                s.settimeout(0.5)
                banner_bytes = s.recv(256)
                banner = banner_bytes.decode("latin-1", errors="ignore").strip()
            except Exception:
                pass
            return True, round(elapsed, 2), banner
        else:
            return False, None, "Connection refused or unreachable"
    except socket.timeout:
        return False, None, "Connection timed out"
    except Exception as e:
        return False, None, f"Socket error: {str(e)}"
    finally:
        s.close()

def check_network_telemetry_status() -> Dict[str, Any]:
    """
    Checks Zeek and Suricata telemetry sources.
    Never fabricates telemetry connections.
    """
    zeek_path = settings.ZEEK_LOG_PATH or os.environ.get("ZEEK_LOG_PATH")
    suricata_path = settings.SURICATA_LOG_PATH or os.environ.get("SURICATA_LOG_PATH")

    zeek_connected = bool(zeek_path and os.path.exists(zeek_path))
    suricata_connected = bool(suricata_path and os.path.exists(suricata_path))

    return {
        "zeek": {
            "name": "zeek",
            "display_name": "Zeek Network Security Monitor",
            "is_configured": bool(zeek_path),
            "status": "connected" if zeek_connected else "not_configured",
            "message": f"Log path: {zeek_path}" if zeek_connected else "Zeek telemetry engine not connected or configured"
        },
        "suricata": {
            "name": "suricata",
            "display_name": "Suricata IDS/IPS Engine",
            "is_configured": bool(suricata_path),
            "status": "connected" if suricata_connected else "not_configured",
            "message": f"Log path: {suricata_path}" if suricata_connected else "Suricata IDS telemetry not connected or configured"
        }
    }
