"""Integration tests for the SentinelSSH REST API.

Uses an isolated temporary SQLite database seeded with sample rows, so tests
never touch the dev/prod database. Run with:

    .venv/bin/python -m pytest backend/tests -q
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Project root on path (for `core`) and backend on path (for `app`).
_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

# Configure an isolated DB BEFORE importing anything that builds the engine.
_TMP_DB = Path(tempfile.mkdtemp()) / "test.sqlite3"
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"

from core.db import init_db, session_scope  # noqa: E402
from core.models import Attack, Command, Incident  # noqa: E402
from app import create_app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    _seed()
    app = create_app()
    app.config.update(TESTING=True, AUTH_REQUIRED=False)
    with app.test_client() as c:
        yield c


def _seed() -> None:
    now = datetime.now(timezone.utc)
    with session_scope() as s:
        inc = Incident(
            source_ip="185.220.100.5", country="Russia",
            first_seen=now, last_seen=now, attempt_count=10, max_risk_score=100,
            status="open", title="SSH activity from 185.220.100.5",
            mitre_techniques=json.dumps(["T1110", "T1105"]),
        )
        s.add(inc)
        s.flush()
        a1 = Attack(
            timestamp=now, source_ip="185.220.100.5", source_port=44321, country="Russia",
            username="root", password="123456", ssh_version="SSH-2.0-libssh",
            session_id="s1", duration=2.5, auth_attempts=5, risk_score=100, risk_level="high",
            is_malicious=True, reputation=100,
            behaviors=json.dumps(["brute_force", "tool_transfer"]),
            mitre_techniques=json.dumps(["T1110", "T1105"]), incident_id=inc.id,
        )
        a1.commands.append(Command(session_id="s1", timestamp=now, command="wget http://x", command_type="shell"))
        a2 = Attack(
            timestamp=now, source_ip="8.8.8.8", source_port=5000, country="United States",
            username="admin", password="admin", ssh_version="SSH-2.0-Go",
            session_id="s2", duration=1.0, auth_attempts=2, risk_score=35, risk_level="medium",
            is_malicious=False, reputation=0,
            behaviors=json.dumps(["brute_force"]), mitre_techniques=json.dumps(["T1110"]),
        )
        s.add_all([a1, a2])


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["data"]["status"] == "ok"


def test_stats(client):
    r = client.get("/api/stats")
    data = r.get_json()["data"]
    assert data["total_attacks"] == 2
    assert data["total_incidents"] == 1
    assert data["unique_ips"] == 2
    assert data["top_mitre"]["id"] == "T1110"


def test_attacks_pagination_and_sort(client):
    r = client.get("/api/attacks?per_page=1&sort=risk_score&order=desc")
    body = r.get_json()
    assert body["success"] is True
    assert body["meta"]["total"] == 2
    assert body["meta"]["per_page"] == 1
    assert body["data"][0]["risk_score"] == 100


def test_attack_detail_includes_commands(client):
    listing = client.get("/api/attacks?source_ip=185.220.100.5").get_json()["data"]
    attack_id = listing[0]["id"]
    detail = client.get(f"/api/attacks/{attack_id}").get_json()["data"]
    assert detail["commands"] is not None
    assert detail["mitre"][0]["id"] in {"T1110", "T1105", "T1078"}


def test_attack_not_found(client):
    r = client.get("/api/attacks/99999")
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "not_found"


def test_validation_error(client):
    r = client.get("/api/attacks?sort=banana")
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "validation_error"


def test_incident_detail(client):
    listing = client.get("/api/incidents").get_json()["data"]
    inc_id = listing[0]["id"]
    detail = client.get(f"/api/incidents/{inc_id}").get_json()["data"]
    assert detail["severity"] == "high"
    assert len(detail["related_attacks"]) >= 1
    assert "brute_force" in detail["behaviors"]


def test_search(client):
    r = client.get("/api/search?q=root")
    body = r.get_json()
    assert body["success"] is True
    assert body["meta"]["total"] >= 1


def test_search_requires_query(client):
    r = client.get("/api/search?q=")
    assert r.status_code == 422


def test_attacks_per_hour(client):
    data = client.get("/api/attacks-per-hour?hours=24").get_json()["data"]
    assert len(data) == 24
    assert sum(b["count"] for b in data) == 2  # both seeded attacks are recent


def test_alert_mitre_matches_type(client):
    alerts = client.get("/api/alerts?limit=10").get_json()["data"]
    malware = next(a for a in alerts if a["alert_type"] == "Malware Download")
    assert malware["mitre"]["id"] == "T1105"  # surfaced technique matches the alert


def test_system_health(client):
    h = client.get("/api/system-health").get_json()["data"]
    assert h["database"] == "online"
    assert h["socketio"] == "online"
    assert h["last_event"] is not None


def test_report_executive_json(client):
    data = client.get("/api/reports/executive").get_json()["data"]
    assert data["meta"]["title"] == "Executive Summary"
    assert data["summary"]["total_attacks"] == 2
    assert "top_mitre" in data and "top_countries" in data


def test_report_threats_json(client):
    data = client.get("/api/reports/threats").get_json()["data"]
    assert "top_usernames" in data and "top_passwords" in data
    assert "top_source_ips" in data and "attack_trends" in data


def test_report_incidents_json(client):
    data = client.get("/api/reports/incidents").get_json()["data"]
    assert data["incident_count"] >= 1
    inc = data["incidents"][0]
    assert "severity" in inc and "mitre" in inc and "behaviors" in inc and "timeline" in inc


def test_report_csv(client):
    r = client.get("/api/reports/incidents?format=csv")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert "Incident ID" in r.get_data(as_text=True)


def test_report_pdf(client):
    r = client.get("/api/reports/executive?format=pdf")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.get_data()[:4] == b"%PDF"


def test_report_invalid_format(client):
    r = client.get("/api/reports/executive?format=xml")
    assert r.status_code == 422


def test_top_and_distribution(client):
    assert client.get("/api/top-usernames").status_code == 200
    assert client.get("/api/top-passwords").status_code == 200
    assert client.get("/api/top-countries").status_code == 200
    assert client.get("/api/mitre").status_code == 200
    assert client.get("/api/behaviors").status_code == 200
    dist = client.get("/api/risk-distribution").get_json()["data"]
    assert "by_level" in dist and "by_bucket" in dist
