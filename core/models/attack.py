"""Attack model — one row per honeypot session (TCP connection)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base, BigIntPK


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Attack(Base):
    __tablename__ = "attacks"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Network origin
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Threat-intel enrichment (populated in Phase 4)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reputation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Captured credentials / session metadata
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ssh_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    auth_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Computed risk (Phase 4): 0-100
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), default="low", nullable=False)

    # Behaviour tags + MITRE ATT&CK technique IDs (JSON-encoded lists).
    behaviors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Correlated incident (Phase 4 incident engine).
    incident_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    commands: Mapped[List["Command"]] = relationship(
        "Command",
        back_populates="attack",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="attacks")

    __table_args__ = (
        Index("ix_attacks_timestamp", "timestamp"),
        Index("ix_attacks_source_ip", "source_ip"),
        Index("ix_attacks_country", "country"),
        Index("ix_attacks_username", "username"),
        Index("ix_attacks_password", "password"),
        Index("ix_attacks_risk_score", "risk_score"),
        Index("ix_attacks_session_id", "session_id"),
        Index("ix_attacks_incident_id", "incident_id"),
        # Composite index for repeat-offender / brute-force queries.
        Index("ix_attacks_ip_time", "source_ip", "timestamp"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Attack id={self.id} ip={self.source_ip} risk={self.risk_score}>"
