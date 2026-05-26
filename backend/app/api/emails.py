"""
/api/emails — Upload and triage .eml files
Full pipeline: parse → enrich → YARA → MITRE → score → persist → TheHive → Cortex
"""
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.models.case import Case, Verdict, EscalationLevel
from app.models.ioc import IOC, IOCType
from app.models.audit import AuditLog
from app.services.email_parser import parse_eml
from app.services.enrichment import enrich_iocs
from app.services.risk_scorer import score_case, IOCEnrichment
from app.services.yara_scanner import scan_content
from app.services.mitre_mapper import map_techniques
from app.services.cortex import run_cortex_analysers
from app.services.nis2 import compute_nis2_deadlines
from app.services.thehive import create_thehive_case

router = APIRouter()

_DANGEROUS_EXTS = {".exe", ".vbs", ".js", ".ps1", ".bat", ".cmd", ".scr", ".hta"}
_URGENCY_WORDS  = ["urgent", "account suspended", "verify", "action required",
                   "password", "security alert", "invoice", "payment", "click here"]


def _domain_from_addr(addr: str) -> str:
    m = re.search(r'@([\w.\-]+)', addr or "")
    return m.group(1).lower() if m else ""


def _ioc_risk(e: IOCEnrichment) -> float:
    score = 0.0
    if e.vt_score is not None:
        score += e.vt_score * 100 * 0.5
    if e.abuseipdb_score is not None:
        score += e.abuseipdb_score * 0.3
    if e.misp_hits:
        score += min(100.0, e.misp_hits * 25) * 0.2
    return round(min(100.0, score), 1)


@router.post("/upload", summary="Upload and triage a .eml file")
async def upload_email(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    # ── 1. Parse ───────────────────────────────────────────────────────────────
    parsed = parse_eml(raw)

    # ── 2. YARA scan ──────────────────────────────────────────────────────────
    yara_result = None
    if settings.enable_yara:
        attachment_bytes = []
        for att in parsed.attachments:
            # re-extract attachment bytes for YARA
            pass  # bytes already hashed; scan body only in this version
        yara_result = scan_content(
            body_text=parsed.plain_text,
            html_body=parsed.html_body,
        )

    # ── 3. IOC enrichment ─────────────────────────────────────────────────────
    ioc_pairs = (
        [(u, "url")    for u in parsed.urls[:20]]
        + [(ip, "ip")  for ip in parsed.ips[:20]]
        + [(h, "hash") for h in parsed.hashes[:10]]
        + [(d, "domain") for d in parsed.domains[:10]]
    )
    enrichments = await enrich_iocs(ioc_pairs)

    # ── 4. MITRE ATT&CK mapping ───────────────────────────────────────────────
    subject_lower = (parsed.subject or "").lower()
    has_urgency = any(w in subject_lower for w in _URGENCY_WORDS)
    sender_domain  = _domain_from_addr(parsed.sender)
    replyto_domain = _domain_from_addr(parsed.reply_to)
    has_reply_mismatch = bool(sender_domain and replyto_domain and sender_domain != replyto_domain)
    has_dangerous_att  = any(
        att.get("filename", "").lower().endswith(tuple(_DANGEROUS_EXTS))
        for att in parsed.attachments
    )

    mitre_techniques = []
    if settings.enable_mitre:
        techniques = map_techniques(
            ioc_types=list({ioc_type for _, ioc_type in ioc_pairs}),
            spf=parsed.spf,
            dkim=parsed.dkim,
            dmarc=parsed.dmarc,
            has_reply_to_mismatch=has_reply_mismatch,
            has_urgency=has_urgency,
            has_dangerous_attachment=has_dangerous_att,
            yara_rule_names=[m.rule_name for m in (yara_result.matches if yara_result else [])],
        )
        mitre_techniques = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "confidence": t.confidence,
                "source": t.source,
            }
            for t in techniques
        ]

    # ── 5. Risk scoring ───────────────────────────────────────────────────────
    scoring = score_case(parsed, enrichments)

    # Boost score from YARA findings
    if yara_result and yara_result.score_contribution > 0:
        yara_boost = yara_result.score_contribution * 0.15
        scoring.total = round(min(100.0, scoring.total + yara_boost), 1)
        if scoring.total >= 60:
            scoring.verdict = "malicious"
        elif scoring.total >= 30:
            scoring.verdict = "suspicious" if scoring.verdict == "benign" else scoring.verdict

    # ── 6. Persist case ───────────────────────────────────────────────────────
    detected_at = datetime.now(timezone.utc)
    early_due, notif_due = compute_nis2_deadlines(detected_at)

    yara_matches_serialised = []
    if yara_result:
        yara_matches_serialised = [
            {
                "rule": m.rule_name,
                "description": m.description,
                "severity": m.severity,
                "mitre": m.mitre,
                "tags": m.tags,
            }
            for m in yara_result.matches
        ]

    case = Case(
        reference=f"PT-{secrets.token_hex(4).upper()}",
        subject=parsed.subject[:512] if parsed.subject else "",
        sender=parsed.sender[:256] if parsed.sender else "",
        recipient=parsed.recipient[:256] if parsed.recipient else "",
        spf=parsed.spf,
        dkim=parsed.dkim,
        dmarc=parsed.dmarc,
        risk_score=scoring.total,
        verdict=Verdict(scoring.verdict),
        escalation=EscalationLevel.L1,
        yara_matches=yara_matches_serialised,
        yara_highest_severity=yara_result.highest_severity if yara_result else "none",
        yara_score_contribution=yara_result.score_contribution if yara_result else 0.0,
        mitre_techniques=mitre_techniques,
        detected_at=detected_at,
        early_warning_due=early_due,
        notification_due=notif_due,
    )
    db.add(case)
    await db.flush()

    # ── 7. Persist IOCs ───────────────────────────────────────────────────────
    for enrichment in enrichments:
        ioc = IOC(
            case_id=case.id,
            ioc_type=IOCType(enrichment.ioc_type),
            value=enrichment.value,
            vt_score=enrichment.vt_score,
            abuseipdb_score=enrichment.abuseipdb_score,
            misp_hits=enrichment.misp_hits,
            risk_score=_ioc_risk(enrichment),
            enrichment_raw={
                "vt_score": enrichment.vt_score,
                "abuseipdb_score": enrichment.abuseipdb_score,
                "misp_hits": enrichment.misp_hits,
            },
        )
        db.add(ioc)

    db.add(AuditLog(
        case_id=case.id,
        actor="system",
        action="case_created",
        detail=(
            f"File: {file.filename} | Score: {scoring.total} | Verdict: {scoring.verdict} | "
            f"YARA: {len(yara_matches_serialised)} matches | "
            f"MITRE: {len(mitre_techniques)} techniques"
        ),
    ))
    await db.commit()
    await db.refresh(case)

    # ── 8. TheHive ────────────────────────────────────────────────────────────
    thehive_id = await create_thehive_case(
        reference=case.reference,
        subject=parsed.subject or "",
        sender=parsed.sender or "",
        risk_score=scoring.total,
        verdict=scoring.verdict,
        ioc_summary=[
            {"type": e.ioc_type, "value": e.value, "risk_score": _ioc_risk(e)}
            for e in enrichments
        ],
    )
    if thehive_id:
        case.thehive_case_id = thehive_id
        db.add(AuditLog(
            case_id=case.id,
            actor="system",
            action="thehive_case_created",
            detail=f"TheHive case ID: {thehive_id}",
        ))
        await db.commit()

    # ── 9. Cortex (top 3 highest-risk IOCs only) ──────────────────────────────
    cortex_results = []
    if settings.enable_cortex and enrichments:
        top_iocs = sorted(enrichments, key=lambda e: _ioc_risk(e), reverse=True)[:3]
        for e in top_iocs:
            if e.ioc_type in ("url", "domain", "ip", "hash"):
                cr = await run_cortex_analysers(e.value, e.ioc_type)
                cortex_results.append({
                    "ioc": e.value,
                    "type": e.ioc_type,
                    "highest_level": cr.highest_level,
                    "jobs": len(cr.jobs),
                })
        if cortex_results:
            db.add(AuditLog(
                case_id=case.id,
                actor="system",
                action="cortex_analysis_complete",
                detail=f"{len(cortex_results)} IOCs analysed by Cortex",
            ))
            await db.commit()

    is_significant = scoring.verdict == "malicious" or scoring.total >= settings.nis2_significant_threshold

    return {
        "case_id": case.id,
        "reference": case.reference,
        "verdict": scoring.verdict,
        "risk_score": scoring.total,
        "score_breakdown": scoring.breakdown,
        "ioc_count": len(enrichments),
        "thehive_case_id": thehive_id,
        "yara": {
            "matches": len(yara_matches_serialised),
            "highest_severity": yara_result.highest_severity if yara_result else "none",
            "rules_triggered": [m["rule"] for m in yara_matches_serialised],
        },
        "mitre": {
            "techniques": mitre_techniques[:5],
            "total": len(mitre_techniques),
        },
        "cortex": cortex_results,
        "nis2": {
            "is_significant": is_significant,
            "early_warning_due": early_due.isoformat(),
            "notification_due": notif_due.isoformat(),
        },
    }
