"""Serves the static SOC dashboard (same-origin with the API).

In production nginx serves these files directly; in dev/demo the Flask app
serves them so session-cookie auth works without CORS gymnastics.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, redirect, send_from_directory
from flask_login import current_user

# project_root/frontend
_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

bp = Blueprint("frontend", __name__)


@bp.get("/")
def index():
    from flask import current_app

    if current_app.config.get("AUTH_REQUIRED", True) and not current_user.is_authenticated:
        return redirect("/login")
    return send_from_directory(_FRONTEND_DIR, "index.html")


@bp.get("/login")
def login_page():
    return send_from_directory(_FRONTEND_DIR, "login.html")


@bp.get("/assets/<path:filename>")
def assets(filename: str):
    return send_from_directory(_FRONTEND_DIR / "assets", filename)
