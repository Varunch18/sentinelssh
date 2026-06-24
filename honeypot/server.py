"""SentinelSSH honeypot entry point.

Starts a TCP listener and dispatches each inbound connection to a
`SessionHandler` running in its own daemon thread. Designed to run as a
long-lived service (foreground process inside Docker / systemd).

Usage:
    python -m honeypot.server
"""
from __future__ import annotations

import logging
import signal
import socket
import sys
import threading
from types import FrameType
from typing import Optional

from .capture import CaptureSink, JSONLSink, MultiSink, StdoutSink
from .config import HoneypotConfig
from .session_handler import SessionHandler

logger = logging.getLogger("sentinelssh")


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    # Paramiko is noisy at INFO; keep it at WARNING.
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def _build_sink(config: HoneypotConfig) -> CaptureSink:
    sinks: list[CaptureSink] = [JSONLSink(config.jsonl_path)]
    if config.log_to_stdout:
        sinks.append(StdoutSink())
    # Run the full threat-intel ingest pipeline (enrich -> score -> incident ->
    # persist) when a database is configured.
    if config.database_url:
        try:
            from .pipeline_sink import PipelineSink
            from .realtime_publisher import RealtimePublisher

            publisher = RealtimePublisher()
            # The pipeline callback pushes each processed snapshot to the
            # backend for real-time dashboard broadcast (Phase 6).
            sinks.append(PipelineSink(on_processed=publisher.publish))
            logger.info("ingest pipeline sink enabled (realtime=%s)", publisher.enabled)
        except Exception:  # noqa: BLE001 - never let DB wiring crash startup
            logger.exception("failed to initialise pipeline sink; continuing without it")
    return MultiSink(sinks)


class HoneypotService:
    """Owns the listening socket and the accept loop."""

    def __init__(self, config: Optional[HoneypotConfig] = None) -> None:
        self._config = config or HoneypotConfig()
        self._host_key = self._config.load_or_create_host_key()
        self._sink = _build_sink(self._config)
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def start(self) -> None:
        cfg = self._config
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((cfg.bind_host, cfg.bind_port))
        sock.listen(cfg.backlog)
        sock.settimeout(1.0)  # allows periodic stop-flag checks
        self._sock = sock
        logger.info("SentinelSSH honeypot listening on %s:%d", cfg.bind_host, cfg.bind_port)

        try:
            self._accept_loop()
        finally:
            self._shutdown()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            logger.info("connection from %s:%d", addr[0], addr[1])
            client.settimeout(self._config.session_timeout)
            handler = SessionHandler(
                client_sock=client,
                addr=addr,
                config=self._config,
                host_key=self._host_key,
                sink=self._sink,
            )
            thread = threading.Thread(target=handler.handle, daemon=True)
            thread.start()

    def stop(self, *_: object) -> None:
        logger.info("shutdown requested")
        self._stop.set()

    def _shutdown(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sink.close()
        logger.info("honeypot stopped")


def main() -> None:
    _configure_logging()
    service = HoneypotService()
    signal.signal(signal.SIGINT, service.stop)
    signal.signal(signal.SIGTERM, service.stop)
    service.start()


if __name__ == "__main__":
    main()
