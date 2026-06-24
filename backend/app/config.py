"""Flask configuration classes for the SentinelSSH backend."""
from __future__ import annotations

import os


class BaseConfig:
    API_PREFIX = "/api"

    # Pagination guards
    DEFAULT_PER_PAGE = int(os.getenv("API_DEFAULT_PER_PAGE", 25))
    MAX_PER_PAGE = int(os.getenv("API_MAX_PER_PAGE", 100))

    # CORS origins for the dashboard (comma-separated). "*" in dev.
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    JSON_SORT_KEYS = False
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

    # Real-time (Phase 6)
    INTERNAL_API_TOKEN = os.getenv("INTERNAL_API_TOKEN")  # shared secret with honeypot
    SOCKETIO_MESSAGE_QUEUE = os.getenv("SOCKETIO_MESSAGE_QUEUE")  # e.g. redis://redis:6379/0

    # Auth (Phase 7)
    AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "true").lower() in {"1", "true", "yes", "on"}
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Demo mode: auto-seed sample data on startup when the DB is empty.
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}

    # Critical-incident threshold (risk score).
    CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", 90))


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    # Secure cookies require HTTPS. Default on for production, but overridable
    # so the stack also works over plain HTTP on localhost (Docker demo).
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() in {"1", "true", "yes", "on"}


def get_config() -> type[BaseConfig]:
    env = os.getenv("FLASK_ENV", "development").lower()
    return ProductionConfig if env in {"production", "prod"} else DevelopmentConfig
