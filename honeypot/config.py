"""Configuration for the SentinelSSH honeypot service.

All settings are environment-driven so the same image runs unchanged across
development and production. A host key is generated on first run if absent.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import paramiko


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


@dataclass
class HoneypotConfig:
    """Runtime configuration for the SSH honeypot."""

    # Network
    bind_host: str = field(default_factory=lambda: os.getenv("HONEYPOT_HOST", "0.0.0.0"))
    bind_port: int = field(default_factory=lambda: _get_int("HONEYPOT_PORT", 2222))
    backlog: int = field(default_factory=lambda: _get_int("HONEYPOT_BACKLOG", 100))

    # Identity / banner — mimic a common OpenSSH server to look authentic.
    ssh_banner: str = field(
        default_factory=lambda: os.getenv(
            "HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        )
    )
    fake_hostname: str = field(default_factory=lambda: os.getenv("HONEYPOT_HOSTNAME", "srv01"))

    # Host key persistence (RSA key generated on first run if missing).
    host_key_path: Path = field(
        default_factory=lambda: Path(os.getenv("HONEYPOT_HOST_KEY", "keys/host_rsa.key"))
    )
    host_key_bits: int = field(default_factory=lambda: _get_int("HONEYPOT_HOST_KEY_BITS", 2048))

    # Session limits — prevent resource abuse / hung sockets.
    auth_timeout: float = field(default_factory=lambda: float(_get_int("HONEYPOT_AUTH_TIMEOUT", 30)))
    session_timeout: float = field(
        default_factory=lambda: float(_get_int("HONEYPOT_SESSION_TIMEOUT", 300))
    )
    max_auth_attempts: int = field(
        default_factory=lambda: _get_int("HONEYPOT_MAX_AUTH_ATTEMPTS", 6)
    )
    max_commands: int = field(default_factory=lambda: _get_int("HONEYPOT_MAX_COMMANDS", 100))

    # Capture sinks
    jsonl_path: Path = field(
        default_factory=lambda: Path(os.getenv("HONEYPOT_JSONL", "data/captures.jsonl"))
    )
    log_to_stdout: bool = field(default_factory=lambda: _get_bool("HONEYPOT_LOG_STDOUT", True))

    # Database sink (wired in Phase 3; ignored if empty for now).
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))

    def load_or_create_host_key(self) -> paramiko.RSAKey:
        """Load the persistent RSA host key, generating it on first run."""
        key_path = self.host_key_path
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return paramiko.RSAKey(filename=str(key_path))
        key = paramiko.RSAKey.generate(self.host_key_bits)
        key.write_private_key_file(str(key_path))
        return key
