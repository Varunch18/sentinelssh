"""Behaviour detection engine.

Analyses a captured session (credentials + commands + history) and emits a set
of behaviour tags, each linked to MITRE ATT&CK techniques. The risk engine
consumes these tags; the dashboard/reports display them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Sequence

from core.intel.config import IntelConfig


@dataclass
class BehaviorContext:
    """Inputs to behaviour detection (decoupled from ORM / transport)."""

    username: str | None
    password: str | None
    commands: Sequence[str]
    auth_attempts: int
    prior_attempts: int  # attempts from same IP within the history window
    is_malicious_ip: bool


@dataclass
class BehaviorResult:
    behaviors: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)  # MITRE technique IDs

    def add(self, behavior: str, *technique_ids: str) -> None:
        if behavior not in self.behaviors:
            self.behaviors.append(behavior)
        for tid in technique_ids:
            if tid not in self.techniques:
                self.techniques.append(tid)


# Command pattern -> (behaviour label, *technique ids)
_COMMAND_RULES = [
    (re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b", re.I), "tool_transfer", ("T1105",)),
    (re.compile(r"\b(uname|lscpu|cat\s+/proc/cpuinfo|hostnamectl)\b", re.I), "system_discovery", ("T1082",)),
    (re.compile(r"\b(whoami|id)\b", re.I), "user_discovery", ("T1033",)),
    (re.compile(r"/etc/(passwd|shadow)", re.I), "account_discovery", ("T1087",)),
    (re.compile(r"authorized_keys|\.ssh/", re.I), "ssh_key_persistence", ("T1098.004",)),
    (re.compile(r"\b(crontab|/etc/cron)", re.I), "cron_persistence", ("T1053.003",)),
    (re.compile(r"\b(xmrig|minerd|stratum\+tcp|\.miner)\b", re.I), "cryptomining", ("T1496",)),
    (re.compile(r"\b(iptables\s+-F|ufw\s+disable|setenforce\s+0)\b", re.I), "disable_defenses", ("T1562.001",)),
    (re.compile(r"\b(chmod\s+\+x|sh\s+\S+\.sh|\./\S+)\b", re.I), "script_execution", ("T1059",)),
    (re.compile(r"\b(arp|nmap|ping\s+-c|ip\s+neigh)\b", re.I), "remote_discovery", ("T1018",)),
]


def classify_command(command: str) -> List[str]:
    """Map a single command to MITRE ATT&CK technique IDs (best-effort)."""
    techniques: List[str] = []
    for pattern, _label, techs in _COMMAND_RULES:
        if pattern.search(command):
            for t in techs:
                if t not in techniques:
                    techniques.append(t)
    return techniques


class BehaviorDetector:
    """Stateless detector; all tuning comes from IntelConfig."""

    def __init__(self, config: IntelConfig) -> None:
        self._config = config

    def detect(self, ctx: BehaviorContext) -> BehaviorResult:
        result = BehaviorResult()

        # Authentication-driven behaviours.
        if ctx.username and ctx.username.lower() in self._config.brute_force_usernames:
            result.add("common_credential_use", "T1078")
        total_attempts = ctx.auth_attempts + ctx.prior_attempts
        if total_attempts >= self._config.repeated_attempts_threshold:
            result.add("brute_force", "T1110", "T1110.001")
        if ctx.prior_attempts > 0:
            result.add("repeat_offender", "T1110")
        if ctx.is_malicious_ip:
            result.add("known_malicious_source")

        # Command-driven behaviours.
        for cmd in ctx.commands:
            for pattern, label, techniques in _COMMAND_RULES:
                if pattern.search(cmd):
                    result.add(label, *techniques)

        # Any interactive activity at all on an SSH honeypot is suspicious.
        if ctx.commands:
            result.add("post_auth_activity", "T1021.004")

        return result
