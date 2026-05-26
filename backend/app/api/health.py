"""Health check"""
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "mode": "mock" if settings.use_mock_stubs else "live",
        "nis2_org": settings.nis2_org_name,
    }
