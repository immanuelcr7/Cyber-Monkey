from fastapi import APIRouter
from app.api.routes import health, assessments, targets, recon

api_router = APIRouter()

# Register routes
api_router.include_router(health.router, tags=["health"])
api_router.include_router(assessments.router, prefix="/assessments", tags=["assessments"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(recon.router, tags=["recon"])
