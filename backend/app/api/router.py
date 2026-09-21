from fastapi import APIRouter
from app.api.routes import health, assessments, targets, recon, vulnerability, standalone

api_router = APIRouter()

# Register routes
api_router.include_router(health.router, tags=["health"])
api_router.include_router(assessments.router, prefix="/assessments", tags=["assessments"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(recon.router, tags=["recon"])
api_router.include_router(vulnerability.router, tags=["vulnerability"])
api_router.include_router(standalone.router, prefix="/standalone", tags=["standalone"])
api_router.include_router(standalone.router, prefix="/pentest", tags=["pentest"])



