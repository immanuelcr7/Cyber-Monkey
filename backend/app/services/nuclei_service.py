import subprocess
import json
import time
import re
from typing import Tuple, Optional, Dict, Any, List

def check_nuclei_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks if the Nuclei CLI binary is installed and accessible via PATH.
    Executes `nuclei -version` safely via subprocess.
    """
    try:
        res = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False
        )
        output = (res.stdout or "") + (res.stderr or "")
        match = re.search(r"Nuclei Engine Version:\s*(v[0-9]+\.[0-9]+\.[0-9]+)", output, re.IGNORECASE)
        if match:
            return True, match.group(1)
        
        # Fallback regex search for version
        match_alt = re.search(r"v[0-9]+\.[0-9]+\.[0-9]+", output)
        if match_alt:
            return True, match_alt.group(0)

        if res.returncode == 0:
            return True, output.strip()
        return False, None
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False, None

def execute_nuclei_scan(
    target_val: str,
    profile: str = "BASIC",
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Executes a real Nuclei scan using `nuclei -u <target_val> -jsonl` via subprocess.
    Parses output line-by-line JSONL and returns structured findings.
    """
    start_time = time.time()
    findings: List[Dict[str, Any]] = []
    error_output: Optional[str] = None
    scan_status = "completed"

    cmd = ["nuclei", "-u", target_val, "-jsonl"]

    # Profile adjustments if specified
    if profile.upper() == "CRITICAL":
        cmd.extend(["-severity", "critical,high"])
    elif profile.upper() == "MEDIUM":
        cmd.extend(["-severity", "critical,high,medium"])

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        duration = round(time.time() - start_time, 2)

        if res.returncode != 0 and not res.stdout.strip():
            scan_status = "failed"
            error_output = (res.stderr or "").strip() or f"Nuclei exited with code {res.returncode}"

        # Parse JSONL output from stdout
        for line in (res.stdout or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                classification = info.get("classification", {})

                template_id = data.get("template-id") or data.get("templateID") or "unknown"
                name = info.get("name") or template_id
                severity = (info.get("severity") or "info").lower()
                
                # Extract CVEs if present
                cves = classification.get("cve-id")
                if isinstance(cves, str):
                    cves = [cves]
                
                # Extract references if present
                references = info.get("reference")
                if isinstance(references, str):
                    references = [references]

                cvss_score = classification.get("cvss-score")
                if isinstance(cvss_score, (int, float)):
                    cvss_score = float(cvss_score)
                else:
                    cvss_score = None

                finding = {
                    "template_id": template_id,
                    "name": name,
                    "severity": severity,
                    "type": data.get("type"),
                    "host": data.get("host"),
                    "matched_at": data.get("matched-at") or data.get("host") or target_val,
                    "description": info.get("description"),
                    "references": references,
                    "cves": cves,
                    "cvss_score": cvss_score,
                    "raw_result": data
                }
                findings.append(finding)
            except json.JSONDecodeError:
                # Gracefully skip malformed JSON lines
                continue

    except FileNotFoundError:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = "Nuclei executable not found in system PATH."
    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = f"Nuclei scan timed out after {timeout} seconds."
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        scan_status = "failed"
        error_output = f"Nuclei scan failed: {str(e)}"

    return {
        "status": scan_status,
        "duration": duration,
        "finding_count": len(findings),
        "findings": findings,
        "error_output": error_output
    }
