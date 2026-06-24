#!/bin/sh
# Backend container entrypoint:
#   1. wait for PostgreSQL to accept connections
#   2. create the schema (init_db)
#   3. ensure a default admin user exists (idempotent)
#   4. launch the Flask + SocketIO server (demo data is seeded by the app
#      factory when DEMO_MODE=true and the DB is empty)
set -e

echo "[entrypoint] waiting for database..."
python - <<'PY'
import os, sys, time
from sqlalchemy import create_engine, text

url = os.environ.get("DATABASE_URL", "")
last = None
for _ in range(60):
    try:
        engine = create_engine(url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("[entrypoint] database is ready")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        last = exc
        time.sleep(2)
print(f"[entrypoint] database not reachable after retries: {last}", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] initializing schema..."
python -c "from core.db import init_db; init_db()"

echo "[entrypoint] ensuring admin user..."
python - <<'PY'
import os
from app.auth.security import create_user

username = os.environ.get("ADMIN_USERNAME", "admin")
password = os.environ.get("ADMIN_PASSWORD", "sentinel123")
try:
    uid = create_user(username, password, role="admin")
    print(f"[entrypoint] created admin user '{username}' (id={uid})")
except ValueError:
    print(f"[entrypoint] admin user '{username}' already exists")
PY

echo "[entrypoint] starting backend on :${PORT:-8008}"
exec python backend/wsgi.py
