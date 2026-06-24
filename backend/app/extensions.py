"""Flask extension singletons.

Kept in their own module so blueprints/services can import them without
creating circular imports with the application factory.
"""
from __future__ import annotations

from flask_login import LoginManager
from flask_socketio import SocketIO

# async_mode="threading" keeps the dev story simple (no eventlet/gevent
# monkey-patching required). In production a message queue (Redis) can be
# supplied via init_app to fan out across multiple workers.
socketio = SocketIO()

# Session-based authentication for the dashboard.
login_manager = LoginManager()
