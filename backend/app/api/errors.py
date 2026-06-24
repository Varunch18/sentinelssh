"""Centralised error handling — every error returns the standard envelope."""
from __future__ import annotations

import logging

from pydantic import ValidationError
from werkzeug.exceptions import HTTPException

from app.utils.responses import ApiError, error

logger = logging.getLogger("sentinelssh.api")


def register_error_handlers(app) -> None:
    @app.errorhandler(ApiError)
    def _handle_api_error(exc: ApiError):
        return error(exc.message, status=exc.status_code, code=exc.code)

    @app.errorhandler(ValidationError)
    def _handle_validation(exc: ValidationError):
        # Summarise pydantic errors into a readable message.
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        return error(f"validation error: {details}", status=422, code="validation_error")

    @app.errorhandler(HTTPException)
    def _handle_http(exc: HTTPException):
        return error(exc.description or exc.name, status=exc.code or 500, code=exc.name.lower().replace(" ", "_"))

    @app.errorhandler(Exception)
    def _handle_unexpected(exc: Exception):
        logger.exception("unhandled error")
        return error("internal server error", status=500, code="internal_error")
