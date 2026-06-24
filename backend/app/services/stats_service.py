"""Stats service — dashboard aggregates, risk distribution, MITRE/behaviour tops."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from core.db import session_scope
from core.intel.mitre import CATALOGUE
from core.models import Attack

from app.repositories.attack_repo import AttackRepository
from app.repositories.incident_repo import IncidentRepository
from app.services import parse_json_list

_BUCKETS = [(0, 10), (11, 20), (21, 30), (31, 40), (41, 50),
            (51, 60), (61, 70), (71, 80), (81, 90), (91, 100)]


class StatsService:
    def __init__(self) -> None:
        self._attacks = AttackRepository()
        self._incidents = IncidentRepository()

    def overview(self) -> Dict[str, Any]:
        with session_scope() as session:
            top_countries = self._attacks.top_countries(session, limit=1)
            top_mitre = self._top_mitre(session, limit=1)
            return {
                "total_attacks": self._attacks.count(session),
                "total_incidents": self._incidents.count(session),
                "active_incidents": self._incidents.count_open(session),
                "critical_incidents": self._incidents.count_critical(session, threshold=90),
                "high_risk_incidents": self._incidents.count_high_risk(session, threshold=70),
                "unique_ips": self._attacks.unique_ips(session),
                "top_country": top_countries[0][0] if top_countries else None,
                "top_mitre": top_mitre[0] if top_mitre else None,
                "last_24h": self._attacks.count_since(session, hours=24),
            }

    def risk_distribution(self) -> Dict[str, Any]:
        with session_scope() as session:
            level_counts = dict(self._attacks.risk_level_counts(session))
            by_level = [
                {"label": level, "count": level_counts.get(level, 0)}
                for level in ("low", "medium", "high")
            ]
            # Histogram buckets over raw risk_score.
            from sqlalchemy import select

            scores = [int(s) for s in session.scalars(select(Attack.risk_score)).all()]
            by_bucket = []
            for lo, hi in _BUCKETS:
                count = sum(1 for s in scores if lo <= s <= hi)
                by_bucket.append({"label": f"{lo}-{hi}", "count": count})
            return {"by_level": by_level, "by_bucket": by_bucket}

    def attacks_per_hour(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Hourly attack counts over the trailing window (server-side bucketing)."""
        hours = max(1, min(hours, 168))
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        # Pre-seed every hour bucket so the chart has a continuous x-axis.
        buckets: List[Dict[str, Any]] = []
        index: Dict[datetime, Dict[str, Any]] = {}
        for i in range(hours - 1, -1, -1):
            slot = now - timedelta(hours=i)
            entry = {"label": slot.strftime("%H:00"), "hour": slot.isoformat(), "count": 0}
            buckets.append(entry)
            index[slot] = entry

        with session_scope() as session:
            for ts in self._attacks.timestamps_since(session, hours):
                aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                slot = aware.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
                entry = index.get(slot)
                if entry is not None:
                    entry["count"] += 1
        return buckets

    def top_mitre(self, limit: int, hours: Optional[int]) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return self._top_mitre(session, limit, hours)

    def _top_mitre(self, session, limit: int = 10, hours: Optional[int] = None) -> List[Dict[str, Any]]:
        raw = self._attacks.fetch_json_column(session, Attack.mitre_techniques, hours)
        counter: Counter = Counter()
        for blob in raw:
            for tid in parse_json_list(blob):
                counter[tid] += 1
        result = []
        for tid, count in counter.most_common(limit):
            tech = CATALOGUE.get(tid)
            result.append({
                "id": tid,
                "name": tech.name if tech else tid,
                "tactic": tech.tactic if tech else "",
                "count": count,
            })
        return result

    def top_behaviors(self, limit: int, hours: Optional[int]) -> List[Dict[str, Any]]:
        with session_scope() as session:
            raw = self._attacks.fetch_json_column(session, Attack.behaviors, hours)
            counter: Counter = Counter()
            for blob in raw:
                for b in parse_json_list(blob):
                    counter[b] += 1
            return [{"value": b, "count": c} for b, c in counter.most_common(limit)]
