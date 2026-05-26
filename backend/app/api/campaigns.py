"""
/api/campaigns — Email campaign detection endpoint
"""
from datetime import timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.case import Case
from app.models.ioc import IOC, IOCType
from app.services.campaign_detector import detect_campaigns

router = APIRouter()


@router.get("/", summary="Detect phishing campaigns across all cases")
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).order_by(Case.created_at))
    cases = result.scalars().all()

    # Build url_domains per case from IOC table
    case_dicts = []
    for c in cases:
        ioc_result = await db.execute(
            select(IOC).where(IOC.case_id == c.id, IOC.ioc_type == IOCType.DOMAIN)
        )
        domains = [i.value for i in ioc_result.scalars().all()]
        detected = c.detected_at
        if detected and detected.tzinfo is None:
            from datetime import timezone
            detected = detected.replace(tzinfo=timezone.utc)
        case_dicts.append({
            "id": c.id,
            "sender": c.sender or "",
            "subject": c.subject or "",
            "url_domains": domains,
            "verdict": c.verdict.value,
            "detected_at": detected,
        })

    campaigns = detect_campaigns(case_dicts)

    return {
        "total_campaigns": len(campaigns),
        "campaigns": [
            {
                "campaign_id": camp.campaign_id,
                "case_ids": camp.case_ids,
                "case_count": len(camp.case_ids),
                "similarity_score": camp.similarity_score,
                "shared_indicators": camp.shared_indicators,
                "first_seen": camp.first_seen.isoformat(),
                "last_seen": camp.last_seen.isoformat(),
                "verdict": camp.verdict,
            }
            for camp in campaigns
        ],
    }
