import os
import io
import csv
import json
import uuid
import hashlib
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

def compute_file_sha256(filepath: str) -> Optional[str]:
    """Computes SHA-256 hash of a file on disk in streaming chunks."""
    if not os.path.exists(filepath):
        return None
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()

def ingest_forensic_evidence_file(
    filename: str,
    file_bytes: bytes,
    storage_dir: str
) -> Tuple[str, str, int]:
    """
    Saves forensic evidence bytes to restricted read-only storage and computes acquisition hash.
    Returns: (storage_identifier, acquisition_sha256, file_size)
    """
    os.makedirs(storage_dir, exist_ok=True)
    storage_id = f"{uuid.uuid4().hex}.bin"
    file_path = os.path.join(storage_dir, storage_id)

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    # Set read-only
    try:
        os.chmod(file_path, 0o444)
    except Exception:
        pass

    return storage_id, sha256, len(file_bytes)

def verify_evidence_hash_on_disk(
    storage_dir: str,
    storage_identifier: str,
    acquisition_sha256: str
) -> Dict[str, Any]:
    """
    Re-hashes evidence file on disk and verifies against initial acquisition hash.
    """
    file_path = os.path.join(storage_dir, storage_identifier)
    now = datetime.utcnow()

    if not os.path.exists(file_path):
        return {
            "status": "FILE_NOT_FOUND",
            "acquisition_sha256": acquisition_sha256,
            "computed_sha256": None,
            "matches": False,
            "verification_timestamp": now,
            "message": "Evidence file could not be located in secure forensic repository."
        }

    computed = compute_file_sha256(file_path)
    if computed == acquisition_sha256:
        return {
            "status": "VERIFIED",
            "acquisition_sha256": acquisition_sha256,
            "computed_sha256": computed,
            "matches": True,
            "verification_timestamp": now,
            "message": "Evidence integrity verified. SHA-256 matches acquisition record exactly."
        }
    else:
        return {
            "status": "TAMPERED",
            "acquisition_sha256": acquisition_sha256,
            "computed_sha256": computed,
            "matches": False,
            "verification_timestamp": now,
            "message": "CRITICAL INTEGRITY FAILURE: Stored evidence hash differs from acquisition hash!"
        }

def export_case_to_json(case_dict: Dict[str, Any]) -> str:
    """Exports case, evidence, chain of custody, and timeline to formatted JSON string."""
    return json.dumps(case_dict, default=str, indent=2)

def export_timeline_to_csv(timeline_events: List[Dict[str, Any]]) -> str:
    """Exports timeline events to RFC 4180 CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Source", "Host", "User Account", "Severity", "Description"])
    for ev in timeline_events:
        writer.writerow([
            ev.get("timestamp"),
            ev.get("event_source"),
            ev.get("source_host") or "",
            ev.get("user_account") or "",
            ev.get("severity"),
            ev.get("event_description")
        ])
    return output.getvalue()
