from fastapi import APIRouter
from app.api.routes import (
    health,
    assessments,
    targets,
    recon,
    vulnerability,
    standalone,
    soc,
    osint,
    malware,
    forensics,
    network_monitoring,
    ai,
    integrations,
)

api_router = APIRouter()

# Register routes
api_router.include_router(health.router, tags=["health"])
api_router.include_router(assessments.router, prefix="/assessments", tags=["assessments"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(recon.router, tags=["recon"])
api_router.include_router(vulnerability.router, tags=["vulnerability"])
api_router.include_router(standalone.router, prefix="/standalone", tags=["standalone"])
api_router.include_router(standalone.router, prefix="/pentest", tags=["pentest"])

# Remaining 5 Cyber Security Workspaces + AI + Integrations
api_router.include_router(soc.router, prefix="/soc", tags=["soc"])
api_router.include_router(osint.router, prefix="/osint", tags=["osint"])
api_router.include_router(malware.router, prefix="/malware", tags=["malware"])
api_router.include_router(forensics.router, prefix="/forensics", tags=["forensics"])
api_router.include_router(network_monitoring.router, prefix="/network-monitoring", tags=["network-monitoring"])
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])



