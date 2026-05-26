"""
IOC model — one row per extracted indicator.
"""
import enum

from sqlalchemy import String, Integer, Float, ForeignKey, JSON, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class IOCType(str, enum.Enum):
    URL    = "url"
    IP     = "ip"
    DOMAIN = "domain"
    HASH   = "hash"
    EMAIL  = "email"


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int]          = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int]     = mapped_column(Integer, ForeignKey("cases.id"), index=True)
    ioc_type: Mapped[IOCType] = mapped_column(Enum(IOCType))
    value: Mapped[str]       = mapped_column(String(2048), index=True)

    # Enrichment results
    vt_score: Mapped[float]        = mapped_column(Float, nullable=True)
    vt_detections: Mapped[int]     = mapped_column(Integer, nullable=True)
    vt_total: Mapped[int]          = mapped_column(Integer, nullable=True)
    abuseipdb_score: Mapped[float] = mapped_column(Float, nullable=True)
    misp_hits: Mapped[int]         = mapped_column(Integer, default=0)
    enrichment_raw: Mapped[dict]   = mapped_column(JSON, nullable=True)

    # Composite risk for this IOC (0–100)
    risk_score: Mapped[float]      = mapped_column(Float, default=0.0)

    case = relationship("Case", back_populates="iocs")
