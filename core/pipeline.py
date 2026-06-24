"""Ingest pipeline: Capture -> Enrichment -> Risk -> Behaviour -> Incident -> DB.

This is the single orchestration point for turning a raw honeypot capture into
an enriched, scored, correlated and persisted record. It is intentionally
decoupled from the honeypot transport (it accepts plain dataclasses, not ORM or
Paramiko objects) so it can also be reused for batch replay or testing.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select

from core.db import session_scope
from core.intel.behavior import BehaviorContext, BehaviorDetector
from core.intel.config import IntelConfig
from core.intel.enrichment import EnrichmentService
from core.intel.incidents import IncidentEngine
from core.intel.mitre import resolve as resolve_mitre
from core.intel.reputation import ReputationService
from core.intel.risk import RiskContext, RiskEngine
from core.models import Attack, Command

logger = logging.getLogger("sentinelssh.pipeline")


@dataclass
class CapturedCommand:
    timestamp: str
    command: str
    command_type: str = "shell"


@dataclass
class CapturedSession:
    """Transport-agnostic representation of one honeypot session."""

    session_id: str
    timestamp: str
    source_ip: str
    source_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ssh_version: Optional[str] = None
    duration: float = 0.0
    auth_attempts: int = 0
    commands: List[CapturedCommand] = field(default_factory=list)


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


class IngestPipeline:
    """Composes the intel services and persists enriched attack records."""

    def __init__(self, config: Optional[IntelConfig] = None) -> None:
        self._config = config or IntelConfig()
        self._enrichment = EnrichmentService(self._config)
        self._reputation = ReputationService(self._config.threat_feed_path)
        self._behavior = BehaviorDetector(self._config)
        self._risk = RiskEngine(self._config)
        self._incidents = IncidentEngine()

    def process(self, capture: CapturedSession) -> Dict[str, Any]:
        """Run the full pipeline for one session; return a snapshot dict."""
        ts = _parse_ts(capture.timestamp)
        command_strings = [c.command for c in capture.commands]

        # --- Enrichment + reputation ---
        enrichment = self._enrichment.enrich(capture.source_ip)
        reputation = self._reputation.check(capture.source_ip)

        with session_scope() as session:
            prior_attempts = self._count_prior_attempts(session, capture.source_ip, ts)

            # --- Behaviour detection ---
            behavior = self._behavior.detect(
                BehaviorContext(
                    username=capture.username,
                    password=capture.password,
                    commands=command_strings,
                    auth_attempts=capture.auth_attempts,
                    prior_attempts=prior_attempts,
                    is_malicious_ip=reputation.is_malicious,
                )
            )

            # --- Risk scoring ---
            risk = self._risk.score(
                RiskContext(
                    enrichment=enrichment,
                    is_malicious_ip=reputation.is_malicious,
                    username=capture.username,
                    auth_attempts=capture.auth_attempts,
                    prior_attempts=prior_attempts,
                    behavior=behavior,
                )
            )

            # --- Build the attack row ---
            attack = Attack(
                timestamp=ts,
                source_ip=capture.source_ip,
                source_port=capture.source_port,
                country=enrichment.country_name or enrichment.country,
                asn=enrichment.asn,
                isp=enrichment.isp,
                reputation=reputation.reputation,
                is_malicious=reputation.is_malicious,
                username=capture.username,
                password=capture.password,
                ssh_version=capture.ssh_version,
                session_id=capture.session_id,
                duration=capture.duration,
                auth_attempts=capture.auth_attempts,
                risk_score=risk.score,
                risk_level=risk.level,
                behaviors=json.dumps(behavior.behaviors),
                mitre_techniques=json.dumps(behavior.techniques),
            )
            for cmd in capture.commands:
                attack.commands.append(
                    Command(
                        session_id=capture.session_id,
                        timestamp=_parse_ts(cmd.timestamp),
                        command=cmd.command,
                        command_type=cmd.command_type,
                    )
                )

            # --- Incident correlation ---
            incident = self._incidents.correlate(
                session,
                source_ip=capture.source_ip,
                country=enrichment.country_name or enrichment.country,
                risk_score=risk.score,
                attempts=max(1, capture.auth_attempts),
                techniques=behavior.techniques,
                timestamp=ts,
            )
            session.flush()  # assign incident.id
            attack.incident_id = incident.id

            session.add(attack)
            session.flush()  # assign attack.id

            snapshot = self._snapshot(attack, behavior.behaviors, behavior.techniques, risk)
            logger.info(
                "ingested session=%s ip=%s risk=%d(%s) incident=%s reasons=%s",
                capture.session_id, capture.source_ip, risk.score, risk.level,
                incident.id, risk.reasons,
            )
            return snapshot

    def _count_prior_attempts(self, session, source_ip: str, before: datetime) -> int:
        window_start = before - timedelta(hours=self._config.history_window_hours)
        stmt = (
            select(func.count(Attack.id))
            .where(Attack.source_ip == source_ip)
            .where(Attack.timestamp >= window_start)
            .where(Attack.timestamp < before)
        )
        return int(session.scalar(stmt) or 0)

    @staticmethod
    def _snapshot(attack: Attack, behaviors: List[str], techniques: List[str], risk) -> Dict[str, Any]:
        return {
            "id": attack.id,
            "timestamp": attack.timestamp.isoformat() if attack.timestamp else None,
            "source_ip": attack.source_ip,
            "source_port": attack.source_port,
            "country": attack.country,
            "asn": attack.asn,
            "isp": attack.isp,
            "username": attack.username,
            "password": attack.password,
            "ssh_version": attack.ssh_version,
            "duration": attack.duration,
            "auth_attempts": attack.auth_attempts,
            "risk_score": attack.risk_score,
            "risk_level": attack.risk_level,
            "is_malicious": attack.is_malicious,
            "behaviors": behaviors,
            "mitre": resolve_mitre(techniques),
            "incident_id": attack.incident_id,
            "command_count": len(attack.commands),
            "risk_reasons": [{"reason": r, "points": p} for r, p in risk.reasons],
        }

    def close(self) -> None:
        self._enrichment.close()
