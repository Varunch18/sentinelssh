"""Free-text search endpoint (IP / username / password / country / session id)."""
from __future__ import annotations

from flask import Blueprint, request

from app.services.attack_service import AttackService
from app.utils.responses import paginated

bp = Blueprint("search", __name__)
_service = AttackService()

_ALLOWED_FIELDS = {"ip", "username", "password", "country", "session_id"}


@bp.get("/search")
def search():
    term = request.args.get("q", "")
    field = request.args.get("field")
    if field and field not in _ALLOWED_FIELDS:
        field = None
    page = min(max(int(request.args.get("page", 1)), 1), 1_000_000)
    per_page = min(max(int(request.args.get("per_page", 25)), 1), 100)
    items, total = _service.search(term, field, page, per_page)
    return paginated(items, page=page, per_page=per_page, total=total, extra={"query": term, "field": field})
