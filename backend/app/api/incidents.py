"""Incident endpoints."""
from __future__ import annotations

from flask import Blueprint

from app.schemas.incident import IncidentQuery
from app.services.incident_service import IncidentService
from app.utils.responses import paginated, success
from app.utils.validation import parse_args

bp = Blueprint("incidents", __name__)
_service = IncidentService()


@bp.get("/incidents")
def list_incidents():
    q = parse_args(IncidentQuery)
    items, total = _service.list(q)
    return paginated(items, page=q.page, per_page=q.per_page, total=total)


@bp.get("/incidents/<int:incident_id>")
def get_incident(incident_id: int):
    return success(_service.get(incident_id))
