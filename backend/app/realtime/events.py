"""SocketIO connection handlers + broadcast helpers.

Event contract (server -> dashboard clients):
  * `new_attack`      : full enriched attack snapshot (see core.pipeline)
  * `stats_update`    : recomputed dashboard counters
  * `incident_update` : incident card summary

Clients connect, receive a `connected` ack, then live updates with no polling.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from app.extensions import socketio

logger = logging.getLogger("sentinelssh.realtime")


def register_socketio_handlers(sio) -> None:
    @sio.on("connect")
    def _on_connect():  # pragma: no cover - exercised via integration
        logger.info("dashboard client connected")
        sio.emit("connected", {"message": "SentinelSSH realtime channel established"})

    @sio.on("disconnect")
    def _on_disconnect():  # pragma: no cover
        logger.info("dashboard client disconnected")


def emit_new_attack(snapshot: Dict[str, Any]) -> None:
    socketio.emit("new_attack", snapshot)


def emit_stats_update(stats: Dict[str, Any]) -> None:
    socketio.emit("stats_update", stats)


def emit_incident_update(incident: Dict[str, Any]) -> None:
    socketio.emit("incident_update", incident)
