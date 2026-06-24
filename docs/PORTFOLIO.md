# SentinelSSH — Portfolio & Recruiter Pack

Copy-paste-ready professional descriptions for GitHub, your CV, and LinkedIn.

---

## GitHub Project Summary (repo "About" / pinned description)

> **SentinelSSH** — a cloud-hosted SSH honeypot with a real-time SOC dashboard.
> Captures live intrusion attempts, enriches them with GeoIP and IP reputation,
> scores risk, classifies attacker behaviour against MITRE ATT&CK, correlates
> incidents, and visualises threats live over WebSockets. Built with Python,
> Flask, PostgreSQL, and Docker; one-command deploy with production guides for
> Nginx + HTTPS on a VPS.

**Short tagline (≤120 chars):**
> Cloud SSH honeypot + real-time SOC dashboard: capture, enrich, MITRE-classify, and report on live attacks.

**Topics/tags:** `cybersecurity` `honeypot` `ssh` `soc` `threat-intelligence`
`mitre-attack` `blue-team` `python` `flask` `postgresql` `docker` `dashboard`
`incident-response`

---

## Project Summary (long-form, for a portfolio site or README intro)

SentinelSSH is an end-to-end blue-team project that emulates a vulnerable SSH
server to attract attackers and convert their activity into actionable threat
intelligence. Every login attempt and command is logged, enriched with
geolocation and reputation data, scored for risk, and mapped to MITRE ATT&CK
techniques. Related activity is correlated into incidents and streamed to a live
security-operations dashboard, with stakeholder-ready PDF/CSV/JSON reporting. The
entire stack is containerised with Docker Compose and ships with a complete
production deployment guide (VPS, Nginx reverse proxy, Let's Encrypt HTTPS, UFW,
systemd, and backups).

---

## CV / Résumé Bullet Points

Pick 3–5; tailor verbs to the role.

- **Designed and built SentinelSSH, a cloud-hosted SSH honeypot and real-time SOC
  dashboard** (Python, Flask, PostgreSQL, Docker) that captures live intrusion
  attempts and converts raw session logs into actionable threat intelligence.
- **Engineered a threat-intelligence pipeline** performing GeoIP/IP-reputation
  enrichment, weighted 0–100 risk scoring, and behaviour-based **MITRE ATT&CK**
  technique classification across 14+ SSH-relevant techniques.
- **Implemented automated incident correlation and a live WebSocket dashboard**
  (Flask-SocketIO, Chart.js) surfacing KPIs, high-risk alerts, and attack trends,
  plus exportable Executive/Threat/Incident reports in PDF, CSV, and JSON.
- **Containerised the full stack with Docker Compose** (honeypot, API, PostgreSQL)
  with health checks, persistent volumes, and a one-command, idempotent startup.
- **Authored production deployment & hardening guides** for Ubuntu VPS — Nginx
  reverse proxy, Let's Encrypt HTTPS, UFW firewall, systemd, and DB backups —
  applying SOC and security best practices throughout.

---

## LinkedIn Project Description

**Title:** SentinelSSH — SSH Honeypot & Real-Time SOC Dashboard

**Description:**

> I built **SentinelSSH**, an end-to-end cybersecurity project that demonstrates
> the full threat-monitoring lifecycle a SOC analyst works through every day.
>
> It runs a cloud-hosted SSH honeypot that lures attackers and records every
> credential and command they attempt. Each session is automatically enriched
> with geolocation and IP-reputation intelligence, assigned a risk score, and
> classified against the **MITRE ATT&CK** framework. Related activity is
> correlated into incidents and streamed live to a security-operations dashboard
> over WebSockets, with one-click Executive, Threat-Activity, and Incident
> reports in PDF/CSV/JSON.
>
> 🛠️ **Tech:** Python, Flask, Flask-SocketIO, SQLAlchemy, PostgreSQL, Paramiko,
> Chart.js, Bootstrap, Docker & Docker Compose, Nginx, Let's Encrypt.
>
> 🔐 **Skills demonstrated:** threat monitoring, log analysis, threat-intelligence
> enrichment, MITRE ATT&CK mapping, incident correlation, credential analysis,
> attack-trend reporting, backend & database engineering, and secure cloud
> deployment (reverse proxy, HTTPS, firewall, systemd, backups).
>
> The whole stack deploys with a single `docker compose up`, and I documented a
> complete production hardening guide for an Ubuntu VPS.
>
> #CyberSecurity #BlueTeam #SOC #ThreatIntelligence #MITREATTACK #Honeypot
> #Python #Docker #DevSecOps

---

## Suggested Pinned-Repo Setup

1. Add screenshots to `docs/screenshots/` (`dashboard.png`, `attack-detail.png`,
   `incidents.png`, `report.png`) — they render in the README.
2. Set the GitHub **About** to the short tagline above and add the topic tags.
3. Pin the repo on your profile and link the live demo URL (from Phase 12) if hosted.
4. Link `docs/DEPLOYMENT.md` and `docs/API.md` from the README (already linked).

---

## Talking Points (for interviews)

- **Why a honeypot?** Safe, legal, high-signal way to study real attacker
  behaviour and practice detection engineering without production risk.
- **Risk scoring design** — weighted signals (brute force, malicious IP, payload
  transfer, defense evasion) bucketed into low/medium/high for triage.
- **Real-time architecture** — the honeypot pushes events to the backend over an
  authenticated internal API; the backend re-broadcasts via SocketIO so the
  dashboard updates without polling.
- **Separation of concerns** — a framework-agnostic `core` intel package is
  shared by both the honeypot and the API, keeping detection logic testable.
- **Production readiness** — health checks, persistent volumes, HTTPS, firewall
  segmentation (honeypot on `:22`, admin SSH relocated), and backups.
