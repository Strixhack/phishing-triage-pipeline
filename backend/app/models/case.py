"""
Case model — one row per triaged email.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Float, DateTime, Enum, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Verdict(str, enum.Enum):
    PENDING    = "pending"
    BENIGN     = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS  = "malicious"


class EscalationLevel(str, enum.Enum):
    L1     = "L1"
    L2     = "L2"
    CISO   = "CISO"
    CLOSED = "closed"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int]            = mapped_column(Integer, primary_key=True, index=True)
    reference: Mapped[str]     = mapped_column(String(32), unique=True, index=True)
    subject: Mapped[str]       = mapped_column(String(512), nullable=True)
    sender: Mapped[str]        = mapped_column(String(256), nullable=True)
    recipient: Mapped[str]     = mapped_column(String(256), nullable=True)

    # Auth results
    spf: Mapped[str]           = mapped_column(String(16), nullable=True)
    dkim: Mapped[str]          = mapped_column(String(16), nullable=True)
    dmarc: Mapped[str]         = mapped_column(String(16), nullable=True)

    # Scoring
    risk_score: Mapped[float]  = mapped_column(Float, default=0.0)
    verdict: Mapped[Verdict]   = mapped_column(Enum(Verdict), default=Verdict.PENDING)

    # YARA results
    yara_matches: Mapped[list]      = mapped_column(JSON, nullable=True)
    yara_highest_severity: Mapped[str] = mapped_column(String(16), nullable=True)
    yara_score_contribution: Mapped[float] = mapped_column(Float, default=0.0)

    # MITRE ATT&CK
    mitre_techniques: Mapped[list]  = mapped_column(JSON, nullable=True)

    # Campaign
    campaign_id: Mapped[str]        = mapped_column(String(32), nullable=True, index=True)

    # Workflow
    escalation: Mapped[EscalationLevel] = mapped_column(
        Enum(EscalationLevel), default=EscalationLevel.L1
    )
    analyst_note: Mapped[str]       = mapped_column(Text, nullable=True)
    thehive_case_id: Mapped[str]    = mapped_column(String(64), nullable=True)

    # NIS2 timers
    detected_at: Mapped[datetime]   = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    early_warning_due: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    notification_due: Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=True)
    notified_at: Mapped[datetime]       = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime]    = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime]    = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    iocs   = relationship("IOC",      back_populates="case", cascade="all, delete-orphan")
    audits = relationship("AuditLog", back_populates="case", cascade="all, delete-orphan")
