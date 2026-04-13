from fastapi import APIRouter

from threat_backend.routers.basic_router import router as basic_router
from threat_backend.routers.threat_intelligence_router import router as threat_intel_router

router = APIRouter()
router.include_router(basic_router)
router.include_router(threat_intel_router)
