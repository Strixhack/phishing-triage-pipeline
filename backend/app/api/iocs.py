"""IOCs endpoint"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.ioc import IOC

router = APIRouter()


@router.get("/", summary="List IOCs, optionally filtered by type or minimum risk score")
async def list_iocs(
    ioc_type: str = None,
    min_score: float = Query(0.0),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    q = select(IOC).order_by(desc(IOC.risk_score)).limit(limit)
    if ioc_type:
        q = q.where(IOC.ioc_type == ioc_type)
    if min_score:
        q = q.where(IOC.risk_score >= min_score)
    result = await db.execute(q)
    iocs = result.scalars().all()
    return [
        {
            "id": i.id,
            "case_id": i.case_id,
            "type": i.ioc_type.value,
            "value": i.value,
            "risk_score": i.risk_score,
            "vt_score": i.vt_score,
            "abuseipdb_score": i.abuseipdb_score,
            "misp_hits": i.misp_hits,
        }
        for i in iocs
    ]
