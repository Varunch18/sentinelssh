"""Internal event-ingest endpoint.

The honeypot process (which runs the ingest pipeline) POSTs each processed
attack snapshot here; the backend then fans it out to dashboard clients over
SocketIO. Protected by a shared secret (`INTERNAL_API_TOKEN`).

This decouples the honeypot from the SocketIO server while keeping a single
authoritative broadcast point. For multi-worker deployments a Redis message
queue can be used instead (see app factory `SOCKETIO_MESSAGE_QUEUE`).
"""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, request

from app.realtime.events import emit_incident_update, emit_new_attack, emit_stats_update
from app.services.incident_service import IncidentService
from app.services.stats_service import StatsService
from app.utils.responses import error, success

logger = logging.getLogger("sentinelssh.api.internal")

bp = Blueprint("internal", __name__)
_stats = StatsService()
_incidents = IncidentService()


def _authorized() -> bool:
    configured = current_app.config.get("INTERNAL_API_TOKEN")
    if not configured:
        # No token configured -> dev mode; allow but warn once per request.
        logger.warning("INTERNAL_API_TOKEN not set; accepting internal event without auth")
        return True
    return request.headers.get("X-Internal-Token") == configured


@bp.post("/internal/events")
def ingest_event():
    if not _authorized():
        return error("invalid internal token", status=403, code="forbidden")

    snapshot = request.get_json(silent=True)
    if not isinstance(snapshot, dict):
        return error("invalid event payload", status=422, code="validation_error")

    # 1) Push the raw attack to the live feed / charts.
    emit_new_attack(snapshot)

    # 2) Recompute and push aggregate counters.
    try:
        emit_stats_update(_stats.overview())
    except Exception:  # noqa: BLE001 - never fail the honeypot on stats errors
        logger.exception("failed to compute stats for broadcast")

    # 3) Push the correlated incident card, if any.
    incident_id = snapshot.get("incident_id")
    if incident_id:
        try:
            summary = _incidents.get_summary(int(incident_id))
            if summary:
                emit_incident_update(summary)
        except Exception:  # noqa: BLE001
            logger.exception("failed to emit incident update")

    return success({"broadcast": True})
