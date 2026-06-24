"""Render report dicts to sectioned CSV text."""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List


def _writer():
    buf = io.StringIO()
    return buf, csv.writer(buf)


def _meta_rows(w, data: Dict[str, Any]) -> None:
    meta = data["meta"]
    w.writerow([meta["product"] + " — " + meta["title"]])
    w.writerow(["Generated", meta["generated_at"]])
    w.writerow([])


def _kv_table(w, title: str, items: List[Dict[str, Any]]) -> None:
    w.writerow([title])
    w.writerow(["Value", "Count"])
    for it in items:
        w.writerow([it.get("value", ""), it.get("count", "")])
    w.writerow([])


def executive_csv(data: Dict[str, Any]) -> str:
    buf, w = _writer()
    _meta_rows(w, data)
    w.writerow(["Executive Summary"])
    for key, val in data["summary"].items():
        w.writerow([key.replace("_", " ").title(), val])
    w.writerow([])
    _kv_table(w, "Top Countries", data["top_countries"])
    w.writerow(["Top MITRE Techniques"])
    w.writerow(["ID", "Name", "Tactic", "Count"])
    for t in data["top_mitre"]:
        w.writerow([t["id"], t["name"], t["tactic"], t["count"]])
    return buf.getvalue()


def threats_csv(data: Dict[str, Any]) -> str:
    buf, w = _writer()
    _meta_rows(w, data)
    _kv_table(w, "Top Usernames", data["top_usernames"])
    _kv_table(w, "Top Passwords", data["top_passwords"])
    _kv_table(w, "Top Source IPs", data["top_source_ips"])
    w.writerow(["Attack Trends (per hour, last 24h)"])
    w.writerow(["Hour", "Attacks"])
    for b in data["attack_trends"]:
        w.writerow([b["label"], b["count"]])
    return buf.getvalue()


def incidents_csv(data: Dict[str, Any]) -> str:
    buf, w = _writer()
    _meta_rows(w, data)
    w.writerow([
        "Incident ID", "Severity", "Risk Score", "Status", "Source IP", "Country",
        "Attempts", "First Seen", "Last Seen", "MITRE Techniques", "Behaviors",
    ])
    for inc in data["incidents"]:
        mitre = "; ".join(t["id"] for t in inc["mitre"])
        behaviors = "; ".join(inc["behaviors"])
        w.writerow([
            inc["id"], inc["severity"], inc["risk_score"], inc["status"],
            inc["source_ip"], inc["country"] or "", inc["attempt_count"],
            inc["timeline"]["first_seen"], inc["timeline"]["last_seen"], mitre, behaviors,
        ])
    return buf.getvalue()


CSV_RENDERERS = {
    "executive": executive_csv,
    "threats": threats_csv,
    "incidents": incidents_csv,
}
