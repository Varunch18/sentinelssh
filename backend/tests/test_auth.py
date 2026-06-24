"""Tests for dashboard authentication + route protection (Phase 7)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

_TMP_DB = Path(tempfile.mkdtemp()) / "auth.sqlite3"
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"

from core.db import init_db  # noqa: E402
from app import create_app  # noqa: E402
from app.auth.security import create_user  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    create_user("analyst", "s3cret", role="analyst")
    app = create_app()
    app.config.update(TESTING=True, AUTH_REQUIRED=True, SECRET_KEY="test")
    with app.test_client() as c:
        yield c


def test_protected_endpoint_requires_auth(client):
    r = client.get("/api/stats")
    assert r.status_code == 401
    assert r.get_json()["error"]["code"] == "unauthorized"


def test_login_invalid(client):
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "wrong"})
    assert r.status_code == 401


def test_login_and_access(client):
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "s3cret"})
    assert r.status_code == 200
    assert r.get_json()["data"]["username"] == "analyst"

    # Session cookie now allows access to protected endpoints.
    r = client.get("/api/stats")
    assert r.status_code == 200

    me = client.get("/api/auth/me")
    assert me.get_json()["data"]["username"] == "analyst"


def test_logout(client):
    client.post("/api/auth/login", json={"username": "analyst", "password": "s3cret"})
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    # After logout, protected access is denied again.
    assert client.get("/api/stats").status_code == 401


def test_internal_endpoint_exempt_from_login(client):
    # The honeypot ingest endpoint must work without a user session.
    r = client.post("/api/internal/events", json={"id": 1, "source_ip": "1.2.3.4"})
    assert r.status_code == 200
