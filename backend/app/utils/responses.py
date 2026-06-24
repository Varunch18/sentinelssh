"""Consistent JSON response envelope + API error type.

All successful responses:   {"success": true, "data": ..., "meta": {...}?}
All error responses:        {"success": false, "error": {"code": ..., "message": ...}}
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from flask import jsonify
from flask.wrappers import Response


class ApiError(Exception):
    """Raised by services/blueprints to return a structured error response."""

    def __init__(self, message: str, status_code: int = 400, code: str = "bad_request") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


def success(data: Any, meta: Optional[Dict[str, Any]] = None, status: int = 200) -> Tuple[Response, int]:
    payload: Dict[str, Any] = {"success": True, "data": data}
    if meta is not None:
        payload["meta"] = meta
    return jsonify(payload), status


def error(message: str, status: int = 400, code: str = "bad_request") -> Tuple[Response, int]:
    return jsonify({"success": False, "error": {"code": code, "message": message}}), status


def paginated(items: Any, *, page: int, per_page: int, total: int, extra: Optional[Dict[str, Any]] = None) -> Tuple[Response, int]:
    pages = (total + per_page - 1) // per_page if per_page else 0
    meta: Dict[str, Any] = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_next": page < pages,
        "has_prev": page > 1,
    }
    if extra:
        meta.update(extra)
    return success(items, meta=meta)
