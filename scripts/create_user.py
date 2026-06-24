"""Create a dashboard user.

Usage (from project root):
    DATABASE_URL="sqlite:///data/sentinelssh.sqlite3" \
    .venv/bin/python scripts/create_user.py <username> <password> [role]
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

from core.db import init_db  # noqa: E402
from app.auth.security import create_user  # noqa: E402


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: create_user.py <username> <password> [role]")
        raise SystemExit(2)
    username, password = sys.argv[1], sys.argv[2]
    role = sys.argv[3] if len(sys.argv) > 3 else "analyst"
    init_db()  # ensure tables exist (no-op if already migrated)
    try:
        uid = create_user(username, password, role)
    except ValueError as exc:
        print(f"error: {exc}")
        raise SystemExit(1)
    print(f"created user '{username}' (id={uid}, role={role})")


if __name__ == "__main__":
    main()
