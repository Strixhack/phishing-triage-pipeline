from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.core.database import get_db
from app.models.case import Case, Verdict, EscalationLevel
from app.models.ioc import IOC
from app.models.audit import AuditLog
from app.services.nis2 import get_nis2_status
router = APIRouter()
def _safe_iso(dt) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
@router.get("/", summary="List all cases")
async def list_cases(
    verdict: Optional[str] = None,
    escalation: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(Case).order_by(desc(Case.created_at)).offset(offset).limit(limit)
    if verdict:
        q = q.where(Case.verdict == verdict)
    if escalation:
        q = q.where(Case.escalation == escalation)
    result = await db.execute(q)
    cases = result.scalars().all()
    count_q = select(func.count()).select_from(Case)
    total = (await db.execute(count_q)).scalar_one()
    return {"total": total, "items": [_case_summary(c) for c in cases]}
@router.get("/stats/summary", summary="Dashboard summary statistics")
async def case_stats(db: AsyncSession = Depends(get_db)):
    total      = (await db.execute(select(func.count()).select_from(Case))).scalar_one()
    pending    = (await db.execute(select(func.count()).select_from(Case).where(Case.verdict == "pending"))).scalar_one()
    suspicious = (await db.execute(select(func.count()).select_from(Case).where(Case.verdict == "suspicious"))).scalar_one()
    malicious  = (await db.execute(select(func.count()).select_from(Case).where(Case.verdict == "malicious"))).scalar_one()
    benign     = (await db.execute(select(func.count()).select_from(Case).where(Case.verdict == "benign"))).scalar_one()
    return {"total": total, "pending": pending, "suspicious": suspicious, "malicious": malicious, "benign": benign}
@router.get("/{case_id}", summary="Get full case details")
async def get_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await _get_or_404(case_id, db)
    iocs_q = select(IOC).where(IOC.case_id == case_id).order_by(desc(IOC.risk_score))
    iocs = (await db.execute(iocs_q)).scalars().all()
    audits_q = select(AuditLog).where(AuditLog.case_id == case_id).order_by(AuditLog.timestamp)
    audits = (await db.execute(audits_q)).scalars().all()
    detected = case.detected_at
    if detected and detected.tzinfo is None:
        detected = detected.replace(tzinfo=timezone.utc)
    nis2 = get_nis2_status(
        risk_score=case.risk_score,
        verdict=case.verdict.value,
        detected_at=detected,
        notified_at=case.notified_at,
    )
    return {
        **_case_summary(case),
        "iocs": [_ioc_detail(i) for i in iocs],
        "audit_log": [_audit_entry(a) for a in audits],
        "nis2": {
            "is_significant": nis2.is_significant,
            "status": nis2.status_label,
            "early_warning_due": _safe_iso(nis2.early_warning_due),
            "notification_due": _safe_iso(nis2.notification_due),
            "hours_until_early_warning": nis2.hours_until_early_warning,
            "hours_until_notification": nis2.hours_until_notification,
        },
    }
class CaseUpdateRequest(BaseModel):
    verdict: Optional[str] = None
    escalation: Optional[str] = None
    analyst_note: Optional[str] = None
    mark_notified: bool = False
    actor: str = "analyst"
@router.patch("/{case_id}", summary="Update case")
async def update_case(case_id: int, body: CaseUpdateRequest, db: AsyncSession = Depends(get_db)):
    case = await _get_or_404(case_id, db)
    changes = []
    if body.verdict:
        try:
            case.verdict = Verdict(body.verdict)
            changes.append(f"verdict -> {body.verdict}")
        except ValueError:
            raise HTTPException(400, f"Invalid verdict: {body.verdict}")
    if body.escalation:
        try:
            case.escalation = EscalationLevel(body.escalation)
            changes.append(f"escalation -> {body.escalation}")
        except ValueError:
            raise HTTPException(400, f"Invalid escalation: {body.escalation}")
    if body.analyst_note is not None:
        case.analyst_note = body.analyst_note
        changes.append("analyst_note updated")
    if body.mark_notified:
        case.notified_at = datetime.now(timezone.utc)
        changes.append("NIS2 notification marked")
    if changes:
        db.add(AuditLog(case_id=case.id, actor=body.actor, action="case_updated", detail=" | ".join(changes)))
        await db.commit()
        await db.refresh(case)
    return _case_summary(case)
async def _get_or_404(case_id: int, db: AsyncSession) -> Case:
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    return case
def _case_summary(c: Case) -> dict:
    return {
        "id": c.id,
        "reference": c.reference,
        "subject": c.subject,
        "sender": c.sender,
        "recipient": c.recipient,
        "spf": c.spf,
        "dkim": c.dkim,
        "dmarc": c.dmarc,
        "risk_score": c.risk_score,
        "verdict": c.verdict.value,
        "escalation": c.escalation.value,
        "analyst_note": c.analyst_note,
        "thehive_case_id": c.thehive_case_id,
        "detected_at": _safe_iso(c.detected_at),
        "created_at": _safe_iso(c.created_at),
        "notified_at": _safe_iso(c.notified_at),
    }
def _ioc_detail(i: IOC) -> dict:
    return {
        "id": i.id,
        "type": i.ioc_type.value,
        "value": i.value,
        "risk_score": i.risk_score,
        "vt_score": i.vt_score,
        "abuseipdb_score": i.abuseipdb_score,
        "misp_hits": i.misp_hits,
    }
def _audit_entry(a: AuditLog) -> dict:
    return {
        "id": a.id,
        "actor": a.actor,
        "action": a.action,
        "detail": a.detail,
        "timestamp": _safe_iso(a.timestamp),
    }
