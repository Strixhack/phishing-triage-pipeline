"""
AuditLog — append-only record of every action taken on a case.
Never update or delete rows from this table.
"""
from datetime import datetime, timezone

from sqlalchemy import String, Integer, ForeignKey, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int]         = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int]    = mapped_column(Integer, ForeignKey("cases.id"), index=True)
    actor: Mapped[str]      = mapped_column(String(64), default="system")
    action: Mapped[str]     = mapped_column(String(128))
    detail: Mapped[str]     = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    case = relationship("Case", back_populates="audits")
