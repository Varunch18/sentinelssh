"""MITRE ATT&CK technique catalogue + helpers for SentinelSSH.

Only the subset of techniques relevant to SSH honeypot activity is included.
Behaviour detection (see behavior.py) references these IDs so the dashboard and
reports can present standards-based attack classification.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    url: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"id": self.id, "name": self.name, "tactic": self.tactic, "url": self.url}


def _t(tid: str, name: str, tactic: str) -> Technique:
    base = tid.replace(".", "/")
    return Technique(id=tid, name=name, tactic=tactic, url=f"https://attack.mitre.org/techniques/{base}/")


CATALOGUE: Dict[str, Technique] = {
    "T1110": _t("T1110", "Brute Force", "Credential Access"),
    "T1110.001": _t("T1110.001", "Password Guessing", "Credential Access"),
    "T1078": _t("T1078", "Valid Accounts", "Defense Evasion"),
    "T1021.004": _t("T1021.004", "Remote Services: SSH", "Lateral Movement"),
    "T1105": _t("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1059": _t("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1082": _t("T1082", "System Information Discovery", "Discovery"),
    "T1033": _t("T1033", "System Owner/User Discovery", "Discovery"),
    "T1087": _t("T1087", "Account Discovery", "Discovery"),
    "T1018": _t("T1018", "Remote System Discovery", "Discovery"),
    "T1098.004": _t("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1053.003": _t("T1053.003", "Scheduled Task/Job: Cron", "Persistence"),
    "T1496": _t("T1496", "Resource Hijacking", "Impact"),
    "T1562.001": _t("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
}


def resolve(technique_ids: List[str]) -> List[Dict[str, str]]:
    """Map technique IDs to full ATT&CK metadata, skipping unknown IDs."""
    out: List[Dict[str, str]] = []
    seen = set()
    for tid in technique_ids:
        if tid in seen:
            continue
        seen.add(tid)
        tech = CATALOGUE.get(tid)
        if tech:
            out.append(tech.to_dict())
    return out
