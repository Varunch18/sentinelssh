#!/usr/bin/env bash
# Render start command for the SentinelSSH dashboard.
#   1. make both `core` and `app` importable
#   2. create the schema
#   3. ensure the admin login exists (idempotent)
#   4. seed demo data once (only if the DB is empty)
#   5. launch the Flask + SocketIO server (binds to Render's $PORT)
set -e

export PYTHONPATH="$PWD:$PWD/backend"

echo "[render] initializing schema..."
python -c "from core.db import init_db; init_db()"

echo "[render] ensuring admin user..."
python - <<'PY'
import os
from app.auth.security import create_user
try:
    uid = create_user(os.environ.get("ADMIN_USERNAME", "admin"),
                      os.environ.get("ADMIN_PASSWORD", "sentinel123"), role="admin")
    print(f"[render] created admin user (id={uid})")
except ValueError:
    print("[render] admin user already exists")
PY

echo "[render] seeding demo data if empty..."
python - <<'PY'
import os
from core.db import session_scope
from core.models import Attack
with session_scope() as s:
    empty = s.query(Attack).first() is None
if empty:
    from scripts.seed_demo_large import generate
    stats = generate(count=int(os.environ.get("SEED_DEMO_COUNT", "550")), reset=False)
    print(f"[render] seeded {stats}")
else:
    print("[render] data already present; skipping seed")
PY

echo "[render] starting dashboard on :${PORT:-8000}"
exec python backend/wsgi.py
