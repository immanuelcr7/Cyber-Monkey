import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Tuple, List, Dict, Any, Optional

def check_nmap_availability() -> Tuple[bool, Optional[str]]:
    """
    Checks if Nmap is installed and returns (installed, version).
    """
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, check=True)
        # Parse the first line to get version details
        lines = result.stdout.splitlines()
        if lines:
            return True, lines[0].strip()
        return True, "Nmap detected (version unknown)"
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False, None

def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    """
    Parses Nmap XML output to extract host and port information.
    """
    ports_list = []
    if not os.path.exists(xml_path):
        return ports_list

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall('host'):
            ports_elem = host.find('ports')
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall('port'):
                port_id = port_elem.attrib.get('portid')
                protocol = port_elem.attrib.get('protocol', 'tcp')
                
                state_elem = port_elem.find('state')
                state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'
                
                service_elem = port_elem.find('service')
                service_name = ''
                version = ''
                if service_elem is not None:
                    service_name = service_elem.attrib.get('name', '')
                    product = service_elem.attrib.get('product', '')
                    ver = service_elem.attrib.get('version', '')
                    extrainfo = service_elem.attrib.get('extrainfo', '')
                    
                    # Combine product, version, and extra info nicely
                    version_parts = [product, ver, extrainfo]
                    version = " ".join([p for p in version_parts if p]).strip()
                
                if port_id:
                    ports_list.append({
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "version": version
                    })
    except Exception as e:
        print(f"Error parsing Nmap XML file: {e}")
    
    return ports_list

def execute_nmap_scan(target_val: str, profile: str) -> Dict[str, Any]:
    """
    Executes a predefined Nmap scan profile against the target.
    Returns a dict with: status, raw_output, error_output, duration, ports
    """
    # 1. Profile mapping
    profile_args_map = {
        "host_discovery": ["-sn"],
        "basic_port": ["-F"],
        "service_detection": ["-sV"],
        "comprehensive": ["-sV", "-sC"]
    }
    
    if profile not in profile_args_map:
        raise ValueError(f"Invalid scan profile: {profile}")
        
    profile_args = profile_args_map[profile]
    
    # 2. Check Nmap presence
    installed, _ = check_nmap_availability()
    if not installed:
        raise RuntimeError("Nmap is not installed on the backend.")

    # 3. Create temp XML path
    fd, temp_xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    
    # 4. Build command safely (no shell=True)
    # We write XML output to temp_xml_path and normal text to stdout (captured)
    cmd = ["nmap"] + profile_args + ["-oX", temp_xml_path, target_val]
    
    # Enforce scan timeouts based on profiles
    timeout = 180 if profile != "comprehensive" else 360
    
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
        
        # Parse XML results
        ports = parse_nmap_xml(temp_xml_path)
        
        # Check return code
        if result.returncode == 0 or result.returncode == 1:
            # returncode 0 is normal success. 
            # returncode 1 is returned by some nmap targets when host seems down, 
            # but we still want to capture stdout and parsed contents.
            return {
                "status": "completed",
                "raw_output": result.stdout,
                "error_output": result.stderr,
                "duration": duration,
                "ports": ports
            }
        else:
            return {
                "status": "failed",
                "raw_output": result.stdout,
                "error_output": f"Nmap execution exited with code {result.returncode}. Error: {result.stderr}",
                "duration": duration,
                "ports": []
            }
            
    except subprocess.TimeoutExpired as te:
        duration = round(time.time() - start_time, 2)
        return {
            "status": "failed",
            "raw_output": te.stdout or "",
            "error_output": f"Nmap scan timed out after {timeout} seconds.",
            "duration": duration,
            "ports": []
        }
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        return {
            "status": "failed",
            "raw_output": "",
            "error_output": f"An unexpected error occurred during scan: {str(e)}",
            "duration": duration,
            "ports": []
        }
    finally:
        # Clean up temp file
        if os.path.exists(temp_xml_path):
            try:
                os.remove(temp_xml_path)
            except Exception:
                pass
