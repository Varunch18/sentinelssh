"""SOC reporting endpoints — executive, threat-activity, incident reports.

Each endpoint supports `?format=json|csv|pdf` (default json).
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, Response, request

from app.reports.builder import ReportBuilder
from app.reports.csv_export import CSV_RENDERERS
from app.reports.pdf import PDF_RENDERERS
from app.utils.responses import error, success

bp = Blueprint("reports", __name__)
_builder = ReportBuilder()

_BUILDERS = {
    "executive": _builder.executive,
    "threats": _builder.threats,
    "incidents": _builder.incidents,
}
_VALID_FORMATS = {"json", "csv", "pdf"}


def _filename(report: str, ext: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return f"sentinelssh-{report}-{stamp}.{ext}"


def _render(report: str):
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in _VALID_FORMATS:
        return error(f"format must be one of {sorted(_VALID_FORMATS)}", status=422, code="validation_error")

    data = _BUILDERS[report]()

    if fmt == "json":
        return success(data)

    if fmt == "csv":
        body = CSV_RENDERERS[report](data)
        return Response(
            body, mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{_filename(report, "csv")}"'},
        )

    # pdf
    body = PDF_RENDERERS[report](data)
    return Response(
        body, mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_filename(report, "pdf")}"'},
    )


@bp.get("/reports/executive")
def executive():
    return _render("executive")


@bp.get("/reports/threats")
def threats():
    return _render("threats")


@bp.get("/reports/incidents")
def incidents():
    return _render("incidents")
