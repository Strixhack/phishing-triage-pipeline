from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from app.core.config import settings
@dataclass
class NIS2Status:
    is_significant: bool
    detected_at: datetime
    early_warning_due: datetime
    notification_due: datetime
    early_warning_overdue: bool
    notification_overdue: bool
    hours_until_early_warning: float
    hours_until_notification: float
    status_label: str
def compute_nis2_deadlines(detected_at: datetime) -> tuple[datetime, datetime]:
    early = detected_at + timedelta(hours=settings.nis2_early_warning_hours)
    final = detected_at + timedelta(hours=settings.nis2_notification_hours)
    return early, final
def _make_aware(dt: datetime) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
def get_nis2_status(
    risk_score: float,
    verdict: str,
    detected_at: datetime,
    notified_at: datetime | None,
) -> NIS2Status:
    now = datetime.now(timezone.utc)
    is_significant = verdict == "malicious" or risk_score >= settings.nis2_significant_threshold
    detected_at = _make_aware(detected_at)
    early_due = _make_aware(detected_at + timedelta(hours=settings.nis2_early_warning_hours))
    notif_due = _make_aware(detected_at + timedelta(hours=settings.nis2_notification_hours))
    hours_to_early = (early_due - now).total_seconds() / 3600
    hours_to_notif = (notif_due - now).total_seconds() / 3600
    early_overdue = now > early_due and notified_at is None
    notif_overdue = now > notif_due and notified_at is None
    if not is_significant:
        label = "not_applicable"
    elif notified_at:
        label = "notified"
    elif notif_overdue:
        label = "overdue"
    elif early_overdue:
        label = "early_warning_due"
    elif hours_to_notif <= 12:
        label = "approaching"
    else:
        label = "on_track"
    return NIS2Status(
        is_significant=is_significant,
        detected_at=detected_at,
        early_warning_due=early_due,
        notification_due=notif_due,
        early_warning_overdue=early_overdue,
        notification_overdue=notif_overdue,
        hours_until_early_warning=round(hours_to_early, 1),
        hours_until_notification=round(hours_to_notif, 1),
        status_label=label,
    )
