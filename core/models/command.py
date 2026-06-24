"""Command model — commands an attacker attempted (logged, never executed)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base, BigIntPK


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    attack_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    command_type: Mapped[str] = mapped_column(String(16), default="shell", nullable=False)

    attack: Mapped["Attack"] = relationship("Attack", back_populates="commands")

    __table_args__ = (
        Index("ix_commands_attack_id", "attack_id"),
        Index("ix_commands_session_id", "session_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Command id={self.id} type={self.command_type} cmd={self.command!r}>"
