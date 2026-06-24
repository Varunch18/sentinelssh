"""Attack service — orchestrates repository queries and serialization."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core.db import session_scope
from core.intel.behavior import classify_command
from core.intel.mitre import resolve as resolve_mitre
from core.models import Attack

from app.repositories.attack_repo import AttackRepository
from app.schemas.attack import AttackOut, CommandOut
from app.services import parse_json_list
from app.utils.responses import ApiError


class AttackService:
    def __init__(self) -> None:
        self._repo = AttackRepository()

    # --- serialization ---
    def _serialize(self, attack: Attack, include_commands: bool = False) -> Dict[str, Any]:
        behaviors = parse_json_list(attack.behaviors)
        techniques = parse_json_list(attack.mitre_techniques)
        commands = None
        if include_commands:
            commands = [CommandOut.model_validate(c) for c in attack.commands]
        out = AttackOut(
            id=attack.id,
            timestamp=attack.timestamp,
            source_ip=attack.source_ip,
            source_port=attack.source_port,
            country=attack.country,
            asn=attack.asn,
            isp=attack.isp,
            username=attack.username,
            password=attack.password,
            ssh_version=attack.ssh_version,
            duration=attack.duration,
            auth_attempts=attack.auth_attempts,
            risk_score=attack.risk_score,
            risk_level=attack.risk_level,
            is_malicious=attack.is_malicious,
            reputation=attack.reputation,
            behaviors=behaviors,
            mitre=resolve_mitre(techniques),
            incident_id=attack.incident_id,
            command_count=len(attack.commands),
            commands=commands,
        )
        return out.model_dump(mode="json")

    # --- queries ---
    def list(self, query) -> Tuple[List[Dict[str, Any]], int]:
        with session_scope() as session:
            items, total = self._repo.paginate(session, query)
            return [self._serialize(a) for a in items], total

    def get(self, attack_id: int) -> Dict[str, Any]:
        with session_scope() as session:
            attack = self._repo.get(session, attack_id)
            if attack is None:
                raise ApiError("attack not found", status_code=404, code="not_found")
            return self._serialize(attack, include_commands=True)

    def recent(self, limit: int) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [self._serialize(a) for a in self._repo.recent(session, limit)]

    def high_risk(self, min_score: int, limit: int) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [self._serialize(a) for a in self._repo.high_risk(session, min_score, limit)]

    def search(self, term: str, field: Optional[str], page: int, per_page: int) -> Tuple[List[Dict[str, Any]], int]:
        if not term or not term.strip():
            raise ApiError("query parameter 'q' is required", status_code=422, code="validation_error")
        with session_scope() as session:
            items, total = self._repo.search(session, term.strip(), field, page, per_page)
            return [self._serialize(a) for a in items], total

    def top_usernames(self, limit: int, hours: Optional[int]) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [{"value": v, "count": c} for v, c in self._repo.top_usernames(session, limit, hours)]

    def top_passwords(self, limit: int, hours: Optional[int]) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [{"value": v, "count": c} for v, c in self._repo.top_passwords(session, limit, hours)]

    def top_countries(self, limit: int, hours: Optional[int]) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [{"value": v, "count": c} for v, c in self._repo.top_countries(session, limit, hours)]

    def top_source_ips(self, limit: int, hours: Optional[int] = None) -> List[Dict[str, Any]]:
        with session_scope() as session:
            return [{"value": v, "count": c} for v, c in self._repo.top_source_ips(session, limit, hours)]

    def recent_commands(self, limit: int) -> List[Dict[str, Any]]:
        with session_scope() as session:
            rows = self._repo.recent_commands(session, limit)
            out: List[Dict[str, Any]] = []
            for command, source_ip in rows:
                out.append({
                    "timestamp": command.timestamp.isoformat() if command.timestamp else None,
                    "session_id": command.session_id,
                    "source_ip": source_ip,
                    "command": command.command,
                    "command_type": command.command_type,
                    "mitre": resolve_mitre(classify_command(command.command)),
                })
            return out
