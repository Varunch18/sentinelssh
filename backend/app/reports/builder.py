"""Assembles structured SOC report payloads from the service layer."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select

from core.db import session_scope
from core.models import Incident

from app.services.attack_service import AttackService
from app.services.incident_service import IncidentService
from app.services.stats_service import StatsService


class ReportBuilder:
    """Produces report dictionaries; rendering is delegated to formatters."""

    def __init__(self) -> None:
        self._attacks = AttackService()
        self._incidents = IncidentService()
        self._stats = StatsService()

    @staticmethod
    def _meta(title: str) -> Dict[str, Any]:
        return {
            "title": title,
            "product": "SentinelSSH",
            "subtitle": "SOC Threat Intelligence Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---- 1. Executive Summary ----
    def executive(self) -> Dict[str, Any]:
        overview = self._stats.overview()
        return {
            "meta": self._meta("Executive Summary"),
            "summary": {
                "total_attacks": overview["total_attacks"],
                "total_incidents": overview["total_incidents"],
                "active_incidents": overview["active_incidents"],
                "critical_incidents": overview["critical_incidents"],
                "unique_ips": overview["unique_ips"],
                "last_24h": overview["last_24h"],
            },
            "top_countries": self._attacks.top_countries(limit=10, hours=None),
            "top_mitre": self._stats.top_mitre(limit=10, hours=None),
        }

    # ---- 2. Threat Activity ----
    def threats(self) -> Dict[str, Any]:
        return {
            "meta": self._meta("Threat Activity Report"),
            "top_usernames": self._attacks.top_usernames(limit=10, hours=None),
            "top_passwords": self._attacks.top_passwords(limit=10, hours=None),
            "top_source_ips": self._attacks.top_source_ips(limit=10, hours=None),
            "attack_trends": self._stats.attacks_per_hour(hours=24),
        }

    # ---- 3. Incident Report ----
    def incidents(self, limit: int = 25) -> Dict[str, Any]:
        with session_scope() as session:
            ids = [
                row[0]
                for row in session.execute(
                    select(Incident.id).order_by(Incident.max_risk_score.desc()).limit(limit)
                ).all()
            ]

        records: List[Dict[str, Any]] = []
        for incident_id in ids:
            detail = self._incidents.get(incident_id)
            records.append({
                "id": detail["id"],
                "source_ip": detail["source_ip"],
                "country": detail["country"],
                "severity": detail["severity"],
                "risk_score": detail["max_risk_score"],
                "status": detail["status"],
                "attempt_count": detail["attempt_count"],
                "mitre": detail["mitre"],
                "behaviors": detail["behaviors"],
                "timeline": {
                    "first_seen": detail["first_seen"],
                    "last_seen": detail["last_seen"],
                },
                "related_attacks": detail["related_attacks"],
            })

        return {
            "meta": self._meta("Incident Report"),
            "incident_count": len(records),
            "incidents": records,
        }
