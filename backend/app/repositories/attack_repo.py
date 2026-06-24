"""Attack repository — pure SQLAlchemy query logic (no HTTP, no serialization)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Sequence, Tuple

from sqlalchemy import Select, distinct, func, or_, select
from sqlalchemy.orm import Session

from core.models import Attack, Command

# Columns exposed for sorting (maps API field -> ORM column).
_SORT_COLUMNS = {
    "timestamp": Attack.timestamp,
    "risk_score": Attack.risk_score,
    "source_ip": Attack.source_ip,
    "country": Attack.country,
    "username": Attack.username,
    "duration": Attack.duration,
}

# Columns searchable via the free-text /search endpoint.
_SEARCH_COLUMNS = {
    "ip": Attack.source_ip,
    "username": Attack.username,
    "password": Attack.password,
    "country": Attack.country,
    "session_id": Attack.session_id,
}


class AttackRepository:
    def get(self, session: Session, attack_id: int) -> Optional[Attack]:
        return session.get(Attack, attack_id)

    def _apply_filters(self, stmt: Select, q) -> Select:
        if q.source_ip:
            stmt = stmt.where(Attack.source_ip == q.source_ip)
        if q.country:
            stmt = stmt.where(Attack.country == q.country)
        if q.username:
            stmt = stmt.where(Attack.username == q.username)
        if q.risk_level:
            stmt = stmt.where(Attack.risk_level == q.risk_level)
        if q.min_risk is not None:
            stmt = stmt.where(Attack.risk_score >= q.min_risk)
        if q.max_risk is not None:
            stmt = stmt.where(Attack.risk_score <= q.max_risk)
        if q.is_malicious is not None:
            stmt = stmt.where(Attack.is_malicious == q.is_malicious)
        if getattr(q, "incident_id", None) is not None:
            stmt = stmt.where(Attack.incident_id == q.incident_id)
        if q.date_from is not None:
            stmt = stmt.where(Attack.timestamp >= q.date_from)
        if q.date_to is not None:
            stmt = stmt.where(Attack.timestamp <= q.date_to)
        return stmt

    def paginate(self, session: Session, q) -> Tuple[Sequence[Attack], int]:
        base = self._apply_filters(select(Attack), q)
        total = session.scalar(select(func.count()).select_from(base.subquery())) or 0

        col = _SORT_COLUMNS.get(q.sort, Attack.timestamp)
        order = col.asc() if q.order == "asc" else col.desc()
        stmt = (
            self._apply_filters(select(Attack), q)
            .order_by(order)
            .offset((q.page - 1) * q.per_page)
            .limit(q.per_page)
        )
        return session.scalars(stmt).all(), int(total)

    def recent(self, session: Session, limit: int) -> Sequence[Attack]:
        stmt = select(Attack).order_by(Attack.timestamp.desc()).limit(limit)
        return session.scalars(stmt).all()

    def high_risk(self, session: Session, min_score: int, limit: int) -> Sequence[Attack]:
        stmt = (
            select(Attack)
            .where(Attack.risk_score >= min_score)
            .order_by(Attack.risk_score.desc(), Attack.timestamp.desc())
            .limit(limit)
        )
        return session.scalars(stmt).all()

    def search(self, session: Session, term: str, field: Optional[str], page: int, per_page: int) -> Tuple[Sequence[Attack], int]:
        like = f"%{term}%"
        if field and field in _SEARCH_COLUMNS:
            condition = _SEARCH_COLUMNS[field].ilike(like)
        else:
            condition = or_(*[c.ilike(like) for c in _SEARCH_COLUMNS.values()])
        base = select(Attack).where(condition)
        total = session.scalar(select(func.count()).select_from(base.subquery())) or 0
        stmt = base.order_by(Attack.timestamp.desc()).offset((page - 1) * per_page).limit(per_page)
        return session.scalars(stmt).all(), int(total)

    # --- aggregations ---
    def _since(self, hours: Optional[int]):
        if not hours:
            return None
        return datetime.now(timezone.utc) - timedelta(hours=hours)

    def top_column(self, session: Session, column, limit: int, hours: Optional[int] = None) -> List[Tuple[str, int]]:
        stmt = select(column, func.count().label("c")).where(column.isnot(None))
        since = self._since(hours)
        if since is not None:
            stmt = stmt.where(Attack.timestamp >= since)
        stmt = stmt.group_by(column).order_by(func.count().desc()).limit(limit)
        return [(row[0], int(row[1])) for row in session.execute(stmt).all()]

    def top_usernames(self, session, limit, hours=None):
        return self.top_column(session, Attack.username, limit, hours)

    def top_passwords(self, session, limit, hours=None):
        return self.top_column(session, Attack.password, limit, hours)

    def top_countries(self, session, limit, hours=None):
        return self.top_column(session, Attack.country, limit, hours)

    def top_source_ips(self, session, limit, hours=None):
        return self.top_column(session, Attack.source_ip, limit, hours)

    def count(self, session: Session) -> int:
        return int(session.scalar(select(func.count(Attack.id))) or 0)

    def count_since(self, session: Session, hours: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        return int(session.scalar(select(func.count(Attack.id)).where(Attack.timestamp >= since)) or 0)

    def unique_ips(self, session: Session) -> int:
        return int(session.scalar(select(func.count(distinct(Attack.source_ip)))) or 0)

    def last_timestamp(self, session: Session):
        return session.scalar(select(func.max(Attack.timestamp)))

    def timestamps_since(self, session: Session, hours: int) -> List[datetime]:
        """Return attack timestamps within the last `hours` (for time-series)."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        stmt = select(Attack.timestamp).where(Attack.timestamp >= since)
        return [row[0] for row in session.execute(stmt).all() if row[0] is not None]

    def recent_commands(self, session: Session, limit: int):
        """Return recent commands joined with their attack's source IP."""
        stmt = (
            select(Command, Attack.source_ip)
            .join(Attack, Command.attack_id == Attack.id)
            .order_by(Command.timestamp.desc())
            .limit(limit)
        )
        return session.execute(stmt).all()

    def risk_level_counts(self, session: Session) -> List[Tuple[str, int]]:
        stmt = select(Attack.risk_level, func.count()).group_by(Attack.risk_level)
        return [(row[0], int(row[1])) for row in session.execute(stmt).all()]

    def fetch_json_column(self, session: Session, column, hours: Optional[int] = None) -> List[str]:
        stmt = select(column).where(column.isnot(None))
        since = self._since(hours)
        if since is not None:
            stmt = stmt.where(Attack.timestamp >= since)
        return [row[0] for row in session.execute(stmt).all() if row[0]]
