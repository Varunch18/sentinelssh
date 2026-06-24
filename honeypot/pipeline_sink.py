"""Capture sink that runs the full ingest pipeline.

Bridges the honeypot's `AttackRecord` to the transport-agnostic
`core.pipeline.CapturedSession`, runs Capture -> Enrichment -> Risk ->
Behaviour -> Incident -> DB, and exposes the resulting snapshot via an optional
callback (used by Phase 6 to push real-time SocketIO events).
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from core.pipeline import CapturedCommand, CapturedSession, IngestPipeline

from .capture import AttackRecord, CaptureSink

logger = logging.getLogger("sentinelssh.pipeline_sink")


class PipelineSink(CaptureSink):
    """Persists captures through the threat-intelligence ingest pipeline."""

    def __init__(self, on_processed: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._pipeline = IngestPipeline()
        self._on_processed = on_processed

    def write(self, record: AttackRecord) -> None:
        capture = CapturedSession(
            session_id=record.session_id,
            timestamp=record.timestamp,
            source_ip=record.source_ip,
            source_port=record.source_port,
            username=record.username,
            password=record.password,
            ssh_version=record.ssh_version,
            duration=record.duration,
            auth_attempts=record.auth_attempts,
            commands=[
                CapturedCommand(timestamp=c.timestamp, command=c.command, command_type=c.command_type)
                for c in record.commands
            ],
        )
        snapshot = self._pipeline.process(capture)
        if self._on_processed is not None:
            try:
                self._on_processed(snapshot)
            except Exception:  # noqa: BLE001 - callbacks must not break ingestion
                logger.exception("on_processed callback failed")

    def close(self) -> None:
        self._pipeline.close()
