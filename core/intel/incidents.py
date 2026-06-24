"""Automatic incident correlation engine.

Groups attacks from the same source IP into a single open `Incident` so the SOC
dashboard shows one actionable card per adversary rather than thousands of raw
events. Updates running aggregates (attempt count, max risk, MITRE coverage).
"""
from __future__ import annotations

import json
import logging
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Incident
from core.models.incident import IncidentStatus

logger = logging.getLogger("sentinelssh.intel.incidents")


class IncidentEngine:
    """Find-or-create open incidents per source IP and keep them current."""

    def correlate(
        self,
        session: Session,
        *,
        source_ip: str,
        country: Optional[str],
        risk_score: int,
        attempts: int,
        techniques: List[str],
        timestamp,
    ) -> Incident:
        incident = session.scalars(
            select(Incident)
            .where(Incident.source_ip == source_ip)
            .where(Incident.status != IncidentStatus.CLOSED)
            .order_by(Incident.last_seen.desc())
            .limit(1)
        ).first()

        if incident is None:
            incident = Incident(
                source_ip=source_ip,
                country=country,
                first_seen=timestamp,
                last_seen=timestamp,
                attempt_count=0,
                max_risk_score=0,
                status=IncidentStatus.OPEN,
                mitre_techniques=json.dumps([]),
            )
            session.add(incident)

        incident.last_seen = timestamp
        incident.attempt_count += max(1, attempts)
        incident.max_risk_score = max(incident.max_risk_score, risk_score)
        if country and not incident.country:
            incident.country = country
        incident.mitre_techniques = json.dumps(
            self._merge_techniques(incident.mitre_techniques, techniques)
        )
        incident.title = self._build_title(incident)
        return incident

    @staticmethod
    def _merge_techniques(existing_json: Optional[str], new: List[str]) -> List[str]:
        try:
            current = json.loads(existing_json) if existing_json else []
        except (TypeError, ValueError):
            current = []
        merged = list(dict.fromkeys([*current, *new]))
        return merged

    @staticmethod
    def _build_title(incident: Incident) -> str:
        loc = f" ({incident.country})" if incident.country else ""
        return f"SSH activity from {incident.source_ip}{loc} — {incident.attempt_count} attempts"
