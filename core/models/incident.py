"""Incident model — groups related attacks from one source into a SOC card."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base, BigIntPK


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IncidentStatus:
    OPEN = "open"
    TRIAGED = "triaged"
    CLOSED = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=IncidentStatus.OPEN, nullable=False)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    attacks: Mapped[List["Attack"]] = relationship("Attack", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_source_ip", "source_ip"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_last_seen", "last_seen"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident id={self.id} ip={self.source_ip} status={self.status}>"
