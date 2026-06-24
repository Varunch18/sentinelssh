"""WSGI entry point.

Dev:   .venv/bin/python backend/wsgi.py
Prod:  gunicorn --chdir backend wsgi:app -b 0.0.0.0:8000
The `core` package must be importable (project root on PYTHONPATH).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure the project root (containing the shared `core` package) is importable.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import create_app  # noqa: E402
from app.extensions import socketio  # noqa: E402

app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    # socketio.run serves both HTTP and WebSocket. allow_unsafe_werkzeug lets
    # the dev server run with the threading async mode.
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=app.config["DEBUG"],
        allow_unsafe_werkzeug=True,
    )
