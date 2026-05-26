"""NIS2 compliance endpoint"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.case import Case
from app.services.nis2 import get_nis2_status

router = APIRouter()


@router.get("/dashboard", summary="NIS2 compliance overview — overdue and at-risk cases")
async def nis2_dashboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Case).where(Case.verdict.in_(["malicious", "suspicious"]))
    )
    cases = result.scalars().all()

    items = []
    for c in cases:
        status = get_nis2_status(
            risk_score=c.risk_score,
            verdict=c.verdict.value,
            detected_at=c.detected_at,
            notified_at=c.notified_at,
        )
        if not status.is_significant:
            continue
        items.append({
            "case_id": c.id,
            "reference": c.reference,
            "risk_score": c.risk_score,
            "verdict": c.verdict.value,
            "status": status.status_label,
            "hours_until_notification": status.hours_until_notification,
            "notification_due": status.notification_due.isoformat(),
            "notified": c.notified_at is not None,
        })

    items.sort(key=lambda x: x["hours_until_notification"])
    return {"significant_cases": items, "total": len(items)}
