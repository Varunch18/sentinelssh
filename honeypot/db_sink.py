"""Database capture sink — persists honeypot sessions to the shared schema.

Maps the honeypot's transport-agnostic `AttackRecord` onto the `core` ORM
models. Enrichment/risk fields are left at defaults here; Phase 4 fills them in
via the ingest pipeline. Kept separate from `capture.py` so the honeypot core
stays free of any database dependency (Dependency Inversion).
"""
from __future__ import annotations

import logging
from datetime import datetime

from core.db import session_scope
from core.models import Attack, Command

from .capture import AttackRecord, CaptureSink

logger = logging.getLogger("sentinelssh.db_sink")


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        from datetime import timezone

        return datetime.now(timezone.utc)


class DatabaseSink(CaptureSink):
    """Persists an `AttackRecord` (and its commands) in a single transaction."""

    def write(self, record: AttackRecord) -> None:
        with session_scope() as session:
            attack = Attack(
                timestamp=_parse_ts(record.timestamp),
                source_ip=record.source_ip,
                source_port=record.source_port,
                username=record.username,
                password=record.password,
                ssh_version=record.ssh_version,
                session_id=record.session_id,
                duration=record.duration,
                auth_attempts=record.auth_attempts,
            )
            for cmd in record.commands:
                attack.commands.append(
                    Command(
                        session_id=record.session_id,
                        timestamp=_parse_ts(cmd.timestamp),
                        command=cmd.command,
                        command_type=cmd.command_type,
                    )
                )
            session.add(attack)
        logger.debug("persisted session %s (%d commands)", record.session_id, len(record.commands))
