"""Seed realistic demo data for screenshots / recruiter demos.

Usage (from project root):
    DATABASE_URL="sqlite:///data/sentinelssh.sqlite3" \
    .venv/bin/python scripts/seed_demo.py [--force] [count]
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))

from core.db import init_db  # noqa: E402
from app.demo_data import seed_if_empty  # noqa: E402


def main() -> None:
    force = "--force" in sys.argv
    nums = [a for a in sys.argv[1:] if a.isdigit()]
    count = int(nums[0]) if nums else 14
    init_db()
    created = seed_if_empty(force=force, count=count)
    if created:
        print(f"seeded {created} demo attacks")
    else:
        print("database already has data (use --force to seed anyway)")


if __name__ == "__main__":
    main()
