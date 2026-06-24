# SentinelSSH REST API

Base URL: `/api` (health check at `/health`).

## Response envelope

All responses share a consistent shape.

**Success**
```json
{ "success": true, "data": <payload>, "meta": { ... }? }
```

**Error**
```json
{ "success": false, "error": { "code": "validation_error", "message": "..." } }
```

| HTTP | code | Meaning |
|------|------|---------|
| 200  | —    | OK |
| 404  | `not_found` | Resource does not exist |
| 422  | `validation_error` | Invalid query parameters |
| 500  | `internal_error` | Unexpected server error |

Paginated endpoints add a `meta` object: `page`, `per_page`, `total`, `pages`, `has_next`, `has_prev`.

---

## Endpoints

### `GET /api/stats`
Dashboard overview.
```json
{ "total_attacks", "total_incidents", "high_risk_incidents", "unique_ips",
  "top_country", "top_mitre": {"id","name","tactic","count"}, "last_24h" }
```

### `GET /api/attacks`
Paginated, filterable, sortable list of attack sessions.

| Param | Type | Notes |
|-------|------|-------|
| `page`, `per_page` | int | `per_page` ≤ 100 |
| `sort` | enum | `timestamp`, `risk_score`, `source_ip`, `country`, `username`, `duration` |
| `order` | enum | `asc`, `desc` |
| `source_ip`, `country`, `username` | str | exact-match filters |
| `risk_level` | enum | `low`, `medium`, `high` |
| `min_risk`, `max_risk` | int | 0–100 |
| `is_malicious` | bool | |
| `incident_id` | int | |
| `date_from`, `date_to` | ISO-8601 | date range on `timestamp` |

### `GET /api/attacks/<id>`
Single attack including `commands[]`, `behaviors[]`, and resolved `mitre[]`. `404` if missing.

### `GET /api/recent?limit=10`
Latest N attacks (newest first).

### `GET /api/high-risk?min_score=71&limit=25`
Attacks at/above a risk threshold, ordered by risk.

### `GET /api/incidents`
Paginated incident cards.

| Param | Notes |
|-------|-------|
| `status` | `open`, `triaged`, `closed` |
| `source_ip` | filter |
| `min_risk` | min `max_risk_score` |
| `sort` | `last_seen`, `first_seen`, `max_risk_score`, `attempt_count` |
| `order` | `asc`, `desc` |

### `GET /api/incidents/<id>`
Incident detail: `severity`, `max_risk_score`, `attempt_count`, `status`, `first_seen`,
`last_seen`, aggregated `behaviors[]`, resolved `mitre[]`, and `related_attacks[]`. `404` if missing.

### `GET /api/top-usernames` · `GET /api/top-passwords` · `GET /api/top-countries`
Top-N credential/country aggregations. Params: `limit` (≤100), optional `hours` (time window).
Returns `[{ "value", "count" }]`.

### `GET /api/mitre?limit=10&hours=24`
Most-observed MITRE ATT&CK techniques: `[{ "id","name","tactic","count" }]`.

### `GET /api/behaviors?limit=10&hours=24`
Most-observed behaviour tags: `[{ "value","count" }]`.

### `GET /api/risk-distribution`
```json
{ "by_level": [{"label":"low|medium|high","count":N}],
  "by_bucket": [{"label":"0-10",...,"91-100","count":N}] }
```

### `GET /api/search?q=<term>&field=<field>&page=&per_page=`
Free-text search across `ip`, `username`, `password`, `country`, `session_id`.
`field` optional (restricts to one column). `q` is required (`422` if empty).

---

## Running

```bash
# dev
DATABASE_URL="sqlite:///data/sentinelssh.sqlite3" PORT=8008 .venv/bin/python backend/wsgi.py

# prod
gunicorn --chdir backend wsgi:app -b 0.0.0.0:8000

# tests
.venv/bin/python -m pytest backend/tests -q
```
