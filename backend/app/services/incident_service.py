"""Incident service — incident cards + detail with related attacks."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.db import session_scope
from core.intel.mitre import resolve as resolve_mitre
from core.models import Incident

from app.repositories.incident_repo import IncidentRepository
from app.schemas.incident import (
    IncidentDetailOut,
    IncidentOut,
    RelatedAttackOut,
)
from app.services import parse_json_list, severity_for
from app.utils.responses import ApiError


class IncidentService:
    def __init__(self) -> None:
        self._repo = IncidentRepository()

    def _summary(self, inc: Incident) -> Dict[str, Any]:
        techniques = parse_json_list(inc.mitre_techniques)
        out = IncidentOut(
            id=inc.id,
            source_ip=inc.source_ip,
            country=inc.country,
            title=inc.title,
            severity=severity_for(inc.max_risk_score),
            max_risk_score=inc.max_risk_score,
            attempt_count=inc.attempt_count,
            status=inc.status,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            mitre=resolve_mitre(techniques),
        )
        return out.model_dump(mode="json")

    def list(self, query) -> Tuple[List[Dict[str, Any]], int]:
        with session_scope() as session:
            items, total = self._repo.paginate(session, query)
            return [self._summary(i) for i in items], total

    def get_summary(self, incident_id: int) -> Dict[str, Any] | None:
        """Lightweight incident card (used for real-time emits)."""
        with session_scope() as session:
            inc = self._repo.get(session, incident_id)
            return self._summary(inc) if inc is not None else None

    def get(self, incident_id: int) -> Dict[str, Any]:
        with session_scope() as session:
            inc = self._repo.get(session, incident_id)
            if inc is None:
                raise ApiError("incident not found", status_code=404, code="not_found")

            behaviors: List[str] = []
            related: List[RelatedAttackOut] = []
            for atk in sorted(inc.attacks, key=lambda a: a.timestamp or 0, reverse=True):
                for b in parse_json_list(atk.behaviors):
                    if b not in behaviors:
                        behaviors.append(b)
                related.append(
                    RelatedAttackOut(
                        id=atk.id,
                        timestamp=atk.timestamp,
                        username=atk.username,
                        password=atk.password,
                        risk_score=atk.risk_score,
                        risk_level=atk.risk_level,
                    )
                )

            detail = IncidentDetailOut(
                id=inc.id,
                source_ip=inc.source_ip,
                country=inc.country,
                title=inc.title,
                severity=severity_for(inc.max_risk_score),
                max_risk_score=inc.max_risk_score,
                attempt_count=inc.attempt_count,
                status=inc.status,
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                mitre=resolve_mitre(parse_json_list(inc.mitre_techniques)),
                behaviors=behaviors,
                related_attacks=related,
            )
            return detail.model_dump(mode="json")
