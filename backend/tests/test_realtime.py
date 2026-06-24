"""Tests for the Phase 6 real-time channel.

Verifies that POSTing an attack snapshot to the internal event endpoint causes
the backend to broadcast `new_attack` and `stats_update` over SocketIO, using
Flask-SocketIO's in-process test client (no network required).
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

_TMP_DB = Path(tempfile.mkdtemp()) / "rt.sqlite3"
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"

from core.db import init_db  # noqa: E402
from app import create_app  # noqa: E402
from app.extensions import socketio  # noqa: E402


@pytest.fixture(scope="module")
def app():
    init_db()
    application = create_app()
    application.config.update(TESTING=True, AUTH_REQUIRED=False)
    return application


def test_internal_event_broadcasts(app):
    http = app.test_client()
    sio = socketio.test_client(app, flask_test_client=http)
    assert sio.is_connected()
    sio.get_received()  # drain the initial `connected` ack

    snapshot = {
        "id": 1, "source_ip": "185.220.100.5", "country": "Russia",
        "username": "root", "risk_score": 100, "risk_level": "high",
        "is_malicious": True, "behaviors": ["brute_force"], "mitre": [],
        "incident_id": None,
    }
    resp = http.post("/api/internal/events", json=snapshot)
    assert resp.status_code == 200
    assert resp.get_json()["data"]["broadcast"] is True

    received = sio.get_received()
    names = [e["name"] for e in received]
    assert "new_attack" in names
    assert "stats_update" in names

    new_attack = next(e for e in received if e["name"] == "new_attack")
    assert new_attack["args"][0]["source_ip"] == "185.220.100.5"


def test_internal_event_rejects_bad_payload(app):
    http = app.test_client()
    resp = http.post("/api/internal/events", data="not-json", content_type="application/json")
    assert resp.status_code == 422


def test_internal_event_token_enforced(app):
    app.config["INTERNAL_API_TOKEN"] = "secret-token"
    http = app.test_client()
    # Missing/incorrect token -> 403
    resp = http.post("/api/internal/events", json={"id": 1}, headers={"X-Internal-Token": "wrong"})
    assert resp.status_code == 403
    # Correct token -> 200
    resp = http.post("/api/internal/events", json={"id": 1}, headers={"X-Internal-Token": "secret-token"})
    assert resp.status_code == 200
    app.config["INTERNAL_API_TOKEN"] = None
