import subprocess
import os
import time
import json
import tempfile
import uuid
import logging
from typing import Tuple, Optional, Dict, Any, List
from app.core.config import settings

logger = logging.getLogger(__name__)

def check_theharvester_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks if theHarvester is installed and available inside the configured path.
    Returns (installed, version_or_error_message).
    """
    path = settings.THEHARVESTER_PATH
    if not os.path.exists(path):
        return False, f"Configured directory does not exist: {path}"

    try:
        # Run uv run theHarvester -h to verify executable environment
        result = subprocess.run(
            ["uv", "run", "theHarvester", "-h"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0:
            # Attempt to parse version from output
            output = result.stdout + "\n" + result.stderr
            for line in output.splitlines():
                if "theharvester" in line.lower() and any(c.isdigit() for c in line):
                    return True, line.strip("* ")
            return True, "theHarvester detected (version unknown)"
        else:
            return False, f"Process exited with non-zero code {result.returncode}: {result.stderr}"
    except FileNotFoundError:
        return False, "uv or theHarvester executable not found on PATH / configured directory."
    except Exception as e:
        return False, f"Error checking availability: {str(e)}"

def execute_theharvester_scan(domain: str) -> Dict[str, Any]:
    """
    Executes the installed theHarvester against an authorized domain target.
    Returns a dict with: status, raw_output, error_output, duration, emails, hosts, ips, names
    """
    # 1. Check availability
    installed, err_msg = check_theharvester_availability()
    if not installed:
        raise RuntimeError(f"theHarvester is not available: {err_msg}")

    # 2. Setup temporary output files
    temp_dir = tempfile.gettempdir()
    temp_base = f"theharvester_{uuid.uuid4().hex}"
    temp_path_base = os.path.join(temp_dir, temp_base)

    # 3. Build command safely (no shell=True, fixed path, argument array)
    # We use environment-configurable passive sources
    sources = settings.THEHARVESTER_SOURCES
    
    cmd = [
        "uv",
        "run",
        "theHarvester",
        "-d", domain,
        "-b", sources,
        "-l", "500",
        "-q",  # Quiet mode: suppress missing API key warnings
        "-f", temp_path_base
    ]

    timeout = int(settings.THEHARVESTER_TIMEOUT)
    start_time = time.time()

    raw_output = ""
    error_output = ""
    status = "failed"
    return_code = None

    emails: Dict[str, str] = {}
    hosts: Dict[str, Dict[str, Any]] = {}
    ips: Dict[str, str] = {}
    names: Dict[str, str] = {}

    # Log the exact command being executed (no secrets exposed)
    logger.info("[theHarvester] CWD: %s", settings.THEHARVESTER_PATH)
    logger.info("[theHarvester] CMD: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            cwd=settings.THEHARVESTER_PATH,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        duration = round(time.time() - start_time, 2)
        raw_output = result.stdout
        error_output = result.stderr
        return_code = result.returncode
        logger.info("[theHarvester] exit code: %d", return_code)

        if result.returncode == 0:
            status = "completed"
            
            # Parse the JSONL output file if it exists (contains source information)
            jsonl_path = temp_path_base + ".jsonl"
            if os.path.exists(jsonl_path):
                try:
                    with open(jsonl_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                if record.get("type") == "summary":
                                    continue
                                kind = record.get("type")
                                value = record.get("value")
                                rec_sources = record.get("sources", [])
                                source_str = ", ".join(rec_sources) if rec_sources else "unknown"

                                if kind == "email" and value:
                                    emails[value.strip().lower()] = source_str
                                elif kind == "hostname" and value:
                                    hosts[value.strip().lower()] = {"ip": None, "source": source_str}
                                elif kind == "ip" and value:
                                    ips[value.strip()] = source_str
                                elif kind in ("person", "linkedin-person", "twitter-person") and value:
                                    names[value.strip()] = source_str
                            except Exception:
                                pass
                except Exception as pe:
                    error_output += f"\n[Parser Warning] Failed to parse JSONL output: {str(pe)}"

            # Parse the standard JSON output file (for hostname-to-IP resolution mappings)
            json_path = temp_path_base + ".json"
            if os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        json_data = json.load(f)
                        
                        # Process hosts mappings which may contain subdomains and IPs
                        for host in json_data.get("hosts", []):
                            if ":" in host:
                                subdomain, ip = host.split(":", 1)
                                subdomain = subdomain.strip().lower()
                                ip = ip.strip()
                                if subdomain in hosts:
                                    hosts[subdomain]["ip"] = ip
                                else:
                                    hosts[subdomain] = {"ip": ip, "source": "unknown"}
                            else:
                                subdomain = host.strip().lower()
                                if subdomain not in hosts:
                                    hosts[subdomain] = {"ip": None, "source": "unknown"}

                        # Fallback for emails
                        for email in json_data.get("emails", []):
                            e = email.strip().lower()
                            if e not in emails:
                                emails[e] = "unknown"

                        # Fallback for IPs
                        for ip in json_data.get("ips", []):
                            i = ip.strip()
                            if i not in ips:
                                ips[i] = "unknown"

                        # Fallback for Names
                        for person in json_data.get("people", []):
                            p = person.strip()
                            if p not in names:
                                names[p] = "unknown"
                        for person in json_data.get("linkedin_people", []):
                            p = person.strip()
                            if p not in names:
                                names[p] = "unknown"
                        for person in json_data.get("twitter_people", []):
                            p = person.strip()
                            if p not in names:
                                names[p] = "unknown"
                except Exception as pe:
                    error_output += f"\n[Parser Warning] Failed to parse JSON output: {str(pe)}"
        else:
            status = "failed"
            logger.error(
                "[theHarvester] process exited with code %d. stderr: %r",
                result.returncode,
                result.stderr
            )
            error_output += f"\n[Execution Error] theHarvester process exited with code {result.returncode}."

    except subprocess.TimeoutExpired as te:
        duration = round(time.time() - start_time, 2)
        status = "failed"
        raw_output = te.stdout or ""
        error_output = te.stderr or ""
        error_output += f"\n[Timeout Error] theHarvester scan timed out after {timeout} seconds."
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        status = "failed"
        error_output += f"\n[Unexpected Error] {str(e)}"

    finally:
        # Clean up temporary output files
        for ext in [".json", ".jsonl", ".xml"]:
            p = temp_path_base + ext
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    return {
        "status": status,
        "raw_output": raw_output,
        "error_output": error_output,
        "duration": duration,
        "return_code": return_code,
        "emails": [{"email": e, "source": src} for e, src in emails.items()],
        "hosts": [{"hostname": h, "ip": d["ip"], "source": d["source"]} for h, d in hosts.items()],
        "ips": [{"ip": i, "source": src} for i, src in ips.items()],
        "names": [{"name": n, "source": src} for n, src in names.items()],
    }
