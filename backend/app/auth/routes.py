"""Authentication endpoints: login / logout / current-user."""
from __future__ import annotations

from flask import Blueprint, request
from flask_login import current_user, login_required, login_user, logout_user

from app.auth.security import authenticate
from app.utils.responses import error, success

bp = Blueprint("auth", __name__)


@bp.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return error("username and password are required", status=422, code="validation_error")

    user = authenticate(username, password)
    if user is None:
        return error("invalid credentials", status=401, code="unauthorized")

    login_user(user, remember=True)
    return success(user.to_dict())


@bp.post("/auth/logout")
@login_required
def logout():
    logout_user()
    return success({"message": "logged out"})


@bp.get("/auth/me")
def me():
    if not current_user.is_authenticated:
        return error("not authenticated", status=401, code="unauthorized")
    return success(current_user.to_dict())
