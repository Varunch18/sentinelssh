"""Incident repository — SQLAlchemy queries for incident cards."""
from __future__ import annotations

from typing import Optional, Sequence, Tuple

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from core.models import Incident

_SORT_COLUMNS = {
    "last_seen": Incident.last_seen,
    "first_seen": Incident.first_seen,
    "max_risk_score": Incident.max_risk_score,
    "attempt_count": Incident.attempt_count,
}


class IncidentRepository:
    def get(self, session: Session, incident_id: int) -> Optional[Incident]:
        stmt = (
            select(Incident)
            .options(selectinload(Incident.attacks))
            .where(Incident.id == incident_id)
        )
        return session.scalars(stmt).first()

    def _apply_filters(self, stmt: Select, q) -> Select:
        if q.status:
            stmt = stmt.where(Incident.status == q.status)
        if q.source_ip:
            stmt = stmt.where(Incident.source_ip == q.source_ip)
        if q.min_risk is not None:
            stmt = stmt.where(Incident.max_risk_score >= q.min_risk)
        return stmt

    def paginate(self, session: Session, q) -> Tuple[Sequence[Incident], int]:
        base = self._apply_filters(select(Incident), q)
        total = session.scalar(select(func.count()).select_from(base.subquery())) or 0

        col = _SORT_COLUMNS.get(q.sort, Incident.last_seen)
        order = col.asc() if q.order == "asc" else col.desc()
        stmt = (
            self._apply_filters(select(Incident), q)
            .order_by(order)
            .offset((q.page - 1) * q.per_page)
            .limit(q.per_page)
        )
        return session.scalars(stmt).all(), int(total)

    def count(self, session: Session) -> int:
        return int(session.scalar(select(func.count(Incident.id))) or 0)

    def count_high_risk(self, session: Session, threshold: int = 70) -> int:
        stmt = select(func.count(Incident.id)).where(Incident.max_risk_score > threshold)
        return int(session.scalar(stmt) or 0)

    def count_open(self, session: Session) -> int:
        stmt = select(func.count(Incident.id)).where(Incident.status != "closed")
        return int(session.scalar(stmt) or 0)

    def count_critical(self, session: Session, threshold: int = 90) -> int:
        stmt = select(func.count(Incident.id)).where(Incident.max_risk_score >= threshold)
        return int(session.scalar(stmt) or 0)
