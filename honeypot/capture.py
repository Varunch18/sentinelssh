"""Capture sinks for honeypot events.

This module defines a small abstraction (`CaptureSink`) so the honeypot does not
depend on any particular storage backend. Phase 2 ships JSONL + stdout sinks.
Phase 3 will add a SQLAlchemy-backed `DatabaseSink` without touching the
honeypot core (Open/Closed principle).
"""
from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("sentinelssh.capture")


@dataclass
class CommandRecord:
    """A single command an attacker attempted (never executed)."""

    timestamp: str
    command: str
    command_type: str  # "shell" | "exec"


@dataclass
class AttackRecord:
    """Full record of one honeypot session (one TCP connection)."""

    session_id: str
    timestamp: str  # connection start, ISO-8601 UTC
    source_ip: str
    source_port: int
    username: str | None = None
    password: str | None = None
    ssh_version: str | None = None
    duration: float = 0.0
    auth_attempts: int = 0
    commands: List[CommandRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaptureSink(ABC):
    """Interface for persisting attack records."""

    @abstractmethod
    def write(self, record: AttackRecord) -> None:  # pragma: no cover - interface
        ...

    def close(self) -> None:  # optional override
        pass


class StdoutSink(CaptureSink):
    """Emits structured JSON lines to the application logger (stdout)."""

    def write(self, record: AttackRecord) -> None:
        logger.info("attack_captured %s", json.dumps(record.to_dict(), ensure_ascii=False))


class JSONLSink(CaptureSink):
    """Append-only JSON Lines file sink. Thread-safe."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AttackRecord) -> None:
        line = json.dumps(record.to_dict(), ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")


class MultiSink(CaptureSink):
    """Fan-out to multiple sinks; a failing sink never breaks the others."""

    def __init__(self, sinks: List[CaptureSink]) -> None:
        self._sinks = sinks

    def write(self, record: AttackRecord) -> None:
        for sink in self._sinks:
            try:
                sink.write(record)
            except Exception:  # noqa: BLE001 - sinks must never crash the honeypot
                logger.exception("capture sink %s failed", sink.__class__.__name__)

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:  # noqa: BLE001
                logger.exception("error closing sink %s", sink.__class__.__name__)
