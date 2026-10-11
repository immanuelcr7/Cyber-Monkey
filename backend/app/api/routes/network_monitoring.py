import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.network_monitoring import NetworkAsset, NetworkService, NetworkEvent
from app.schemas.network_monitoring import (
    NetworkAssetCreate,
    NetworkAssetUpdate,
    NetworkAssetResponse,
    NetworkServiceCreate,
    NetworkServiceResponse,
    NetworkEventResponse,
    NetworkCheckResult,
)
from app.services.network_monitoring_service import probe_port, check_network_telemetry_status
from app.services.nmap_service import check_nmap_availability, execute_nmap_scan

router = APIRouter()

@router.get("/telemetry/status")
def get_telemetry_status():
    """Returns Zeek and Suricata telemetry integration status."""
    return check_network_telemetry_status()

@router.get("/health-summary")
def get_network_health_summary(db: Session = Depends(get_db)):
    """Returns network overview metrics."""
    assets = db.query(NetworkAsset).all()
    total = len(assets)
    up_count = sum(1 for a in assets if a.status == "up")
    down_count = sum(1 for a in assets if a.status == "down")
    total_services = db.query(NetworkService).count()
    recent_events_count = db.query(NetworkEvent).count()

    return {
        "total_assets": total,
        "up_assets": up_count,
        "down_assets": down_count,
        "unknown_assets": total - up_count - down_count,
        "total_monitored_services": total_services,
        "total_events": recent_events_count,
        "system_health": "Healthy" if down_count == 0 else f"{down_count} Assets Down"
    }

@router.get("/assets", response_model=List[NetworkAssetResponse])
def get_assets(
    status_filter: Optional[str] = Query(None, alias="status"),
    asset_type: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists network assets with their monitored services."""
    query = db.query(NetworkAsset)
    if status_filter:
        query = query.filter(NetworkAsset.status == status_filter.lower())
    if asset_type:
        query = query.filter(NetworkAsset.asset_type == asset_type.lower())
    if q:
        search = f"%{q}%"
        query = query.filter(
            (NetworkAsset.ip_address.ilike(search)) |
            (NetworkAsset.hostname.ilike(search)) |
            (NetworkAsset.notes.ilike(search))
        )
    return query.order_by(desc(NetworkAsset.updated_at)).all()

@router.post("/assets", response_model=NetworkAssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(payload: NetworkAssetCreate, db: Session = Depends(get_db)):
    """Registers an authorized network asset for monitoring."""
    clean_ip = payload.ip_address.strip()
    existing = db.query(NetworkAsset).filter(NetworkAsset.ip_address == clean_ip).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Asset with IP '{clean_ip}' is already registered.")

    asset = NetworkAsset(
        ip_address=clean_ip,
        hostname=payload.hostname,
        mac_address=payload.mac_address,
        asset_type=payload.asset_type,
        status="unknown",
        monitored=payload.monitored,
        check_interval_seconds=payload.check_interval_seconds,
        notes=payload.notes
    )
    db.add(asset)
    db.flush()

    # Pre-populate default ports if specified
    if payload.ports:
        for p in payload.ports:
            svc = NetworkService(
                asset_id=asset.id,
                port=p,
                protocol="TCP",
                service_name=f"port-{p}",
                status="unknown"
            )
            db.add(svc)

    db.commit()
    db.refresh(asset)
    return asset

@router.get("/assets/{asset_id}", response_model=NetworkAssetResponse)
def get_asset_detail(asset_id: uuid.UUID, db: Session = Depends(get_db)):
    """Retrieves asset detail and monitored services."""
    asset = db.query(NetworkAsset).filter(NetworkAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Network asset not found.")
    return asset

@router.patch("/assets/{asset_id}", response_model=NetworkAssetResponse)
def update_asset(asset_id: uuid.UUID, payload: NetworkAssetUpdate, db: Session = Depends(get_db)):
    """Updates asset metadata."""
    asset = db.query(NetworkAsset).filter(NetworkAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Network asset not found.")

    if payload.hostname is not None:
        asset.hostname = payload.hostname
    if payload.mac_address is not None:
        asset.mac_address = payload.mac_address
    if payload.asset_type:
        asset.asset_type = payload.asset_type
    if payload.monitored is not None:
        asset.monitored = payload.monitored
    if payload.notes is not None:
        asset.notes = payload.notes

    asset.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(asset)
    return asset

@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: uuid.UUID, db: Session = Depends(get_db)):
    """Deletes an asset and its monitored services."""
    asset = db.query(NetworkAsset).filter(NetworkAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Network asset not found.")
    db.delete(asset)
    db.commit()
    return None

@router.post("/assets/{asset_id}/services", response_model=NetworkServiceResponse, status_code=status.HTTP_201_CREATED)
def add_service_to_asset(asset_id: uuid.UUID, payload: NetworkServiceCreate, db: Session = Depends(get_db)):
    """Adds a monitored port / service to an asset."""
    asset = db.query(NetworkAsset).filter(NetworkAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Network asset not found.")

    existing = db.query(NetworkService).filter(
        NetworkService.asset_id == asset.id,
        NetworkService.port == payload.port,
        NetworkService.protocol == payload.protocol
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Port {payload.port}/{payload.protocol} already registered for this asset.")

    svc = NetworkService(
        asset_id=asset.id,
        port=payload.port,
        protocol=payload.protocol,
        service_name=payload.service_name or "unknown",
        banner=payload.banner,
        status="open"
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    return svc

@router.post("/assets/{asset_id}/check", response_model=NetworkCheckResult)
def check_asset_availability(asset_id: uuid.UUID, db: Session = Depends(get_db)):
    """
    Performs real TCP port connection probe against asset services.
    Measures latency and detects anomalies / status transitions.
    """
    asset = db.query(NetworkAsset).filter(NetworkAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Network asset not found.")

    ports_to_check = [s.port for s in asset.services]
    # If no specific services registered, probe standard ports (80, 443, 22)
    if not ports_to_check:
        ports_to_check = [80, 443]

    open_ports = []
    latencies = []
    for p in ports_to_check:
        is_open, latency, banner = probe_port(asset.ip_address, p)
        # Update matching service record if exists
        svc = next((s for s in asset.services if s.port == p), None)
        if svc:
            svc.status = "open" if is_open else "closed"
            if banner:
                svc.banner = banner
            svc.last_checked = datetime.utcnow()

        if is_open:
            open_ports.append(p)
            if latency:
                latencies.append(latency)

    prev_status = asset.status
    now = datetime.utcnow()
    new_status = "up" if len(open_ports) > 0 else "down"
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    asset.status = new_status
    asset.last_seen = now
    asset.response_time_ms = avg_latency
    asset.updated_at = now

    # Emit anomaly events on state transition
    if prev_status == "up" and new_status == "down":
        evt = NetworkEvent(
            asset_id=asset.id,
            event_type="HOST_DOWN",
            severity="high",
            message=f"Monitored host {asset.ip_address} has stopped responding to TCP probes.",
            details={"checked_ports": ports_to_check}
        )
        db.add(evt)
    elif prev_status == "down" and new_status == "up":
        evt = NetworkEvent(
            asset_id=asset.id,
            event_type="HOST_UP",
            severity="low",
            message=f"Monitored host {asset.ip_address} is back online.",
            details={"open_ports": open_ports}
        )
        db.add(evt)

    db.commit()

    return {
        "asset_id": asset.id,
        "ip_address": asset.ip_address,
        "status": new_status,
        "response_time_ms": avg_latency,
        "services_checked": len(ports_to_check),
        "open_ports": open_ports,
        "timestamp": now
    }

@router.get("/events", response_model=List[NetworkEventResponse])
def get_network_events(limit: int = 50, db: Session = Depends(get_db)):
    """Lists network event log entries."""
    return db.query(NetworkEvent).order_by(desc(NetworkEvent.timestamp)).limit(limit).all()

@router.post("/discover-nmap")
def discover_assets_via_nmap(
    target_value: str = Query(..., description="Target IP or CIDR subnet"),
    authorization_confirmed: bool = Query(False),
    db: Session = Depends(get_db)
):
    """
    Reuses existing Nmap scanner to discover active assets and open ports on authorized network.
    Ingests discovered hosts into network monitoring inventory.
    """
    if not authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Authorization must be explicitly confirmed before running Nmap network discovery."
        )

    installed, err_msg = check_nmap_availability()
    if not installed:
        raise HTTPException(status_code=503, detail=f"Nmap is not available on backend host: {err_msg}")

    scan_res = execute_nmap_scan(target_val=target_value, scan_profile="service_detection")

    # Ingest discovered hosts
    created_count = 0
    clean_ip = target_value.strip()
    asset = db.query(NetworkAsset).filter(NetworkAsset.ip_address == clean_ip).first()
    if not asset:
        asset = NetworkAsset(
            ip_address=clean_ip,
            asset_type="server",
            status="up" if scan_res.get("ports") else "unknown",
            notes=f"Discovered via Nmap scan ({scan_res.get('scan_profile', 'service_detection')})"
        )
        db.add(asset)
        db.flush()
        created_count += 1

    for p_info in scan_res.get("ports", []):
        port_num = p_info.get("port")
        proto = p_info.get("protocol", "tcp").upper()
        existing_svc = db.query(NetworkService).filter(
            NetworkService.asset_id == asset.id,
            NetworkService.port == port_num
        ).first()
        if not existing_svc:
            svc = NetworkService(
                asset_id=asset.id,
                port=port_num,
                protocol=proto,
                service_name=p_info.get("service") or "unknown",
                banner=p_info.get("version") or None,
                status=p_info.get("state") or "open"
            )
            db.add(svc)

    db.commit()

    return {
        "status": "success",
        "target": target_value,
        "assets_created": created_count,
        "ports_discovered": len(scan_res.get("ports", [])),
        "nmap_results": scan_res
    }
