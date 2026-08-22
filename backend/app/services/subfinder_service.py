import subprocess
from typing import Tuple, List, Dict, Any, Optional

def check_subfinder_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks if Subfinder is installed and returns (installed, version).
    """
    try:
        # Standard subfinder flag for version is "-version"
        result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True, check=True)
        # Parse the version line from stdout or stderr
        output = result.stdout + "\n" + result.stderr
        lines = output.splitlines()
        for line in lines:
            if "version" in line.lower():
                return True, line.strip()
        return True, "Subfinder detected (version unknown)"
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False, None

def execute_subfinder_scan(domain: str) -> Dict[str, Any]:
    """
    Executes passive subdomain enumeration using Subfinder.
    Returns a dict with: status, raw_output, error_output, duration, subdomains
    """
    # 1. Check Subfinder presence
    installed, _ = check_subfinder_availability()
    if not installed:
        raise RuntimeError("Subfinder is not installed on the backend.")

    # 2. Build command safely (no shell=True)
    # -silent flag ensures subfinder outputs only discovered subdomains to stdout (one per line)
    cmd = ["subfinder", "-d", domain, "-silent"]
    
    timeout = 180
    
    import time
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        duration = round(time.time() - start_time, 2)
        
        # Check return code
        if result.returncode == 0:
            # Parse lines from stdout to extract subdomains
            # Normalize to lowercase and deduplicate
            lines = result.stdout.splitlines()
            subdomains = []
            for line in lines:
                s = line.strip().lower()
                if s and s not in subdomains:
                    subdomains.append(s)
            
            return {
                "status": "completed",
                "raw_output": result.stdout,
                "error_output": result.stderr,
                "duration": duration,
                "subdomains": subdomains
            }
        else:
            return {
                "status": "failed",
                "raw_output": result.stdout,
                "error_output": f"Subfinder execution exited with code {result.returncode}. Error: {result.stderr}",
                "duration": duration,
                "subdomains": []
            }
            
    except subprocess.TimeoutExpired as te:
        duration = round(time.time() - start_time, 2)
        return {
            "status": "failed",
            "raw_output": te.stdout or "",
            "error_output": f"Subfinder scan timed out after {timeout} seconds.",
            "duration": duration,
            "subdomains": []
        }
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        return {
            "status": "failed",
            "raw_output": "",
            "error_output": f"An unexpected error occurred during scan: {str(e)}",
            "duration": duration,
            "subdomains": []
        }
