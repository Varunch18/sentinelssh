"""Publishes processed attack snapshots to the backend for live broadcast.

Best-effort: any failure is logged and swallowed so real-time delivery never
impacts capture/persistence. Uses the stdlib only (no extra dependency).

Configured via:
  * INTERNAL_EVENTS_URL  e.g. http://backend:8000/api/internal/events
  * INTERNAL_API_TOKEN   shared secret matching the backend
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict

logger = logging.getLogger("sentinelssh.realtime_publisher")


class RealtimePublisher:
    def __init__(self) -> None:
        self._url = os.getenv("INTERNAL_EVENTS_URL", "").strip()
        self._token = os.getenv("INTERNAL_API_TOKEN", "").strip()
        self._timeout = float(os.getenv("INTERNAL_EVENTS_TIMEOUT", "3"))
        if self._url:
            logger.info("realtime publisher enabled -> %s", self._url)

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    def publish(self, snapshot: Dict[str, Any]) -> None:
        if not self._url:
            return
        try:
            data = json.dumps(snapshot).encode("utf-8")
            req = urllib.request.Request(self._url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            if self._token:
                req.add_header("X-Internal-Token", self._token)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("failed to publish realtime event: %s", exc)
        except Exception:  # noqa: BLE001
            logger.exception("unexpected error publishing realtime event")
