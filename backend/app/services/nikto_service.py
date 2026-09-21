import os
import subprocess
import time
import re
import logging
from typing import Tuple, Optional, Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PERL_EXECUTABLE = r"C:\Strawberry\perl\bin\perl.exe"
NIKTO_SCRIPT = r"C:\Users\dhina\Desktop\Cyber Monkey\nikto\program\nikto.pl"


def sanitize_target_and_port(target_val: str, input_port: Optional[int] = None) -> Tuple[str, int]:
    """
    Parses and sanitizes target_val and validates the port.
    Strips schemes (http://, https://), paths, and embedded ports from target_val
    to produce a clean hostname/IP for Nikto's -h flag.
    Validates port is an integer in range 1..65535.
    If input_port is provided and valid (1..65535), it takes precedence.
    Otherwise, if target_val contained an embedded port, that port is used.
    Default fallback port is 80.
    """
    if not target_val or not str(target_val).strip():
        raise ValueError("Target value cannot be empty.")

    target_clean = str(target_val).strip()
    extracted_port = None

    # Handle scheme if present (e.g., http://192.168.1.35:50/path)
    if "://" in target_clean:
        parsed = urlparse(target_clean)
        hostname = parsed.hostname or ""
        if parsed.port:
            extracted_port = parsed.port
        target_clean = hostname
    else:
        # Strip trailing slash or path if present
        if "/" in target_clean:
            target_clean = target_clean.split("/", 1)[0]

        # Handle host:port (e.g. 192.168.1.35:50)
        if ":" in target_clean and not target_clean.startswith("["):
            parts = target_clean.split(":", 1)
            target_clean = parts[0].strip()
            try:
                extracted_port = int(parts[1].strip())
            except ValueError:
                pass

    # Determine final port
    final_port = 80
    if input_port is not None:
        try:
            p = int(input_port)
            if 1 <= p <= 65535:
                final_port = p
            else:
                raise ValueError(f"Port {p} out of valid range (1-65535).")
        except ValueError as e:
            if "out of valid range" in str(e):
                raise
            if extracted_port and 1 <= extracted_port <= 65535:
                final_port = extracted_port
    elif extracted_port and 1 <= extracted_port <= 65535:
        final_port = extracted_port

    if not (1 <= final_port <= 65535):
        raise ValueError(f"Invalid port: {final_port}. Port must be between 1 and 65535.")

    if not target_clean:
        target_clean = str(target_val).strip()

    return target_clean, final_port


def check_nikto_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks if Perl executable and Nikto script exist locally on Windows.
    Executes perl.exe -v safely via subprocess.run(shell=False).
    """
    if not os.path.exists(PERL_EXECUTABLE):
        return False, None
    if not os.path.exists(NIKTO_SCRIPT):
        return False, None

    try:
        res = subprocess.run(
            [PERL_EXECUTABLE, "-v"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False
        )
        if res.returncode == 0:
            return True, "v2.6.1"
        return False, None
    except Exception:
        return False, None


def parse_nikto_output(stdout: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Parses Nikto stdout text into structured finding objects and severity summary.
    Nikto lines usually start with '+ '.
    """
    findings: List[Dict[str, Any]] = []
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    if not stdout:
        return findings, summary

    # Lines to ignore as metadata headers/footers
    ignore_prefixes = (
        "- Nikto v",
        "+ Target IP:",
        "+ Target Hostname:",
        "+ Target Port:",
        "+ Start Time:",
        "+ End Time:",
        "+ Server:",
        "+ 0 host(s) tested",
        "+ 1 host(s) tested",
        "+ 1 host(s) yield",
        "+ 0 host(s) yield"
    )

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("+ "):
            continue

        if any(line.startswith(prefix) for prefix in ignore_prefixes):
            continue

        clean_text = line[2:].strip() # remove "+ "

        # Extract OSVDB / Nikto ID if present
        nikto_id = None
        osvdb_match = re.search(r"(OSVDB-\d+|NIKTO-\d+|CVE-\d{4}-\d+)", clean_text, re.IGNORECASE)
        if osvdb_match:
            nikto_id = osvdb_match.group(1).upper()

        text_without_id = re.sub(r"^(OSVDB-\d+|NIKTO-\d+|CVE-\d{4}-\d+):\s*", "", clean_text, flags=re.IGNORECASE).strip()

        endpoint = None
        title = clean_text

        if text_without_id.startswith("/"):
            if ":" in text_without_id:
                ep_part, desc_part = text_without_id.split(":", 1)
                endpoint = ep_part.strip()
                title = desc_part.strip() or clean_text
            else:
                parts = text_without_id.split(maxsplit=1)
                endpoint = parts[0]
                title = parts[1] if len(parts) > 1 else clean_text
        else:
            path_match = re.search(r"(/[a-zA-Z0-9_\-\.\/]+)", text_without_id)
            if path_match:
                endpoint = path_match.group(1)

        # Determine severity based on security keywords
        lower = clean_text.lower()
        if any(k in lower for k in ["rce", "remote code execution", "sql injection", "command injection", "critical"]):
            severity = "critical"
        elif any(k in lower for k in ["vulnerability", "exploit", "traversal", "xss", "cross site scripting", "arbitrary file"]):
            severity = "high"
        elif any(k in lower for k in ["admin", "config", "credential", "password", "bypass", "sensitive", "backup", "database"]):
            severity = "medium"
        elif any(k in lower for k in ["header", "x-frame-options", "cookie", "directory indexing", "outdated"]):
            severity = "low"
        else:
            severity = "info"

        finding = {
            "nikto_id": nikto_id,
            "title": title[:150],
            "description": clean_text,
            "severity": severity,
            "endpoint": endpoint,
            "evidence": clean_text,
            "remediation": None,
            "raw_line": line
        }
        findings.append(finding)
        summary["total"] += 1
        summary[severity] += 1

    return findings, summary


def execute_nikto_scan(
    target_val: str,
    port: Optional[int] = 80,
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Executes Nikto using local Perl executable and Nikto script via subprocess.run(shell=False).
    Sanitizes target_val and port so Nikto receives a clean host and exact port.
    Constructs command: [perl.exe, nikto.pl, "-h", clean_host, "-p", str(final_port)]
    Logs final command arguments before execution without revealing secrets.
    """
    start_time = time.time()
    findings: List[Dict[str, Any]] = []
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    error_output: Optional[str] = None
    scan_status = "completed"

    try:
        clean_host, final_port = sanitize_target_and_port(target_val, port)
    except ValueError as val_err:
        return {
            "status": "failed",
            "duration": 0.0,
            "finding_count": 0,
            "summary": summary,
            "findings": findings,
            "error_output": f"Invalid target or port: {str(val_err)}",
            "target": str(target_val),
            "port": port or 80
        }

    cmd = [
        PERL_EXECUTABLE,
        NIKTO_SCRIPT,
        "-h",
        clean_host,
        "-p",
        str(final_port)
    ]

    # Requirement 7: Add backend logging showing final Nikto command arguments before execution
    logger.info(f"Executing Nikto scan with command arguments: {cmd}")

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        duration = round(time.time() - start_time, 2)

        stdout = res.stdout or ""
        stderr = res.stderr or ""

        if res.returncode != 0 and not stdout.strip():
            scan_status = "failed"
            error_output = stderr.strip() or f"Nikto exited with code {res.returncode}"
        else:
            findings, summary = parse_nikto_output(stdout)

    except FileNotFoundError as e:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = f"Executable or script not found: {str(e)}"
    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = f"Nikto scan timed out after {timeout} seconds."
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = f"Nikto scan failed: {str(e)}"

    return {
        "status": scan_status,
        "duration": duration,
        "finding_count": len(findings),
        "summary": summary,
        "findings": findings,
        "error_output": error_output,
        "target": clean_host,
        "port": final_port
    }
