"""System health + high-risk alerts services."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from core.db import session_scope
from core.intel.mitre import resolve as resolve_mitre
from core.models import Attack

from app.repositories.attack_repo import AttackRepository
from app.services import parse_json_list

# How recently the honeypot must have produced an event to be "online".
_HONEYPOT_ONLINE_MINUTES = 15

# Behaviour -> (human-friendly alert type, representative MITRE technique).
# Highest priority first; the matched technique is surfaced on the alert card.
_ALERT_TYPES = [
    ("cryptomining", "Cryptomining", "T1496"),
    ("tool_transfer", "Malware Download", "T1105"),
    ("ssh_key_persistence", "Persistence Attempt", "T1098.004"),
    ("cron_persistence", "Persistence Attempt", "T1053.003"),
    ("disable_defenses", "Defense Evasion", "T1562.001"),
    ("account_discovery", "Credential Access", "T1087"),
    ("known_malicious_source", "Known Malicious IP", None),
    ("brute_force", "Brute Force", "T1110"),
]


class SystemService:
    def __init__(self) -> None:
        self._attacks = AttackRepository()

    def health(self) -> Dict[str, Any]:
        db_status = "online"
        last_event: Optional[datetime] = None
        try:
            with session_scope() as session:
                last_event = self._attacks.last_timestamp(session)
        except Exception:  # noqa: BLE001
            db_status = "error"

        honeypot_status = "waiting"
        if last_event is not None:
            now = datetime.now(timezone.utc)
            ts = last_event if last_event.tzinfo else last_event.replace(tzinfo=timezone.utc)
            honeypot_status = "online" if (now - ts) <= timedelta(minutes=_HONEYPOT_ONLINE_MINUTES) else "idle"

        return {
            "database": db_status,
            "socketio": "online",  # served in-process with the API
            "honeypot": honeypot_status,
            "last_event": last_event.isoformat() if last_event else None,
        }

    def alerts(self, limit: int = 10, min_score: int = 71) -> List[Dict[str, Any]]:
        with session_scope() as session:
            rows = self._attacks.high_risk(session, min_score=min_score, limit=limit)
            return [self._to_alert(a) for a in rows]

    def _to_alert(self, attack: Attack) -> Dict[str, Any]:
        behaviors = parse_json_list(attack.behaviors)
        techniques = resolve_mitre(parse_json_list(attack.mitre_techniques))
        alert_type = "Suspicious Login"
        preferred_id: Optional[str] = None
        for behavior, label, technique_id in _ALERT_TYPES:
            if behavior in behaviors:
                alert_type = label
                preferred_id = technique_id
                break

        # Surface the technique that matches the alert type when available.
        mitre = techniques[0] if techniques else None
        if preferred_id:
            match = next((t for t in techniques if t["id"] == preferred_id), None)
            if match is None:
                match = next(iter(resolve_mitre([preferred_id])), None)
            if match is not None:
                mitre = match

        return {
            "id": attack.id,
            "alert_type": alert_type,
            "source_ip": attack.source_ip,
            "country": attack.country,
            "risk_score": attack.risk_score,
            "risk_level": attack.risk_level,
            "mitre": mitre,
            "timestamp": attack.timestamp.isoformat() if attack.timestamp else None,
            "incident_id": attack.incident_id,
        }
