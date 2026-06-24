"""Paramiko ServerInterface implementation for the SentinelSSH honeypot.

Security design:
  * Every authentication attempt is ACCEPTED (so we capture credentials) but
    the session is a sandboxed fake shell — no real OS access is ever granted.
  * Shell / PTY / exec requests are *accepted* so we can log attacker commands,
    but they are handled by our emulated shell, never the host.
  * Direct-tcpip / port-forwarding / SFTP are rejected to prevent the honeypot
    being abused as a pivot.
"""
from __future__ import annotations

import logging
import threading
from typing import List

import paramiko

from .capture import AttackRecord, CommandRecord, utc_now_iso

logger = logging.getLogger("sentinelssh.ssh")


class HoneypotServer(paramiko.ServerInterface):
    """Captures auth + channel activity while granting zero real access."""

    def __init__(self, record: AttackRecord, max_auth_attempts: int) -> None:
        self._record = record
        self._max_auth_attempts = max_auth_attempts
        # Event signalled when an interactive shell is requested.
        self.shell_event = threading.Event()
        # Commands collected from exec requests (non-interactive).
        self.exec_commands: List[str] = []
        # Terminal dimensions requested (used to render a believable prompt).
        self.term = "xterm"

    # --- Channels -----------------------------------------------------------
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        # Reject forwarding/tunnelling so the honeypot can't be used as a pivot.
        logger.info("rejected channel kind=%s session=%s", kind, self._record.session_id)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # --- Authentication -----------------------------------------------------
    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        self._record.auth_attempts += 1
        # Always store the most recent credential pair.
        self._record.username = username
        self._record.password = password
        logger.info(
            "auth_password session=%s user=%r pass=%r attempt=%d",
            self._record.session_id,
            username,
            password,
            self._record.auth_attempts,
        )
        # Accept after capturing — but cap attempts to avoid endless loops.
        if self._record.auth_attempts > self._max_auth_attempts:
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Record the attempt but force fallback to password so we capture creds.
        self._record.auth_attempts += 1
        self._record.username = username
        logger.info(
            "auth_publickey session=%s user=%r key_type=%s",
            self._record.session_id,
            username,
            key.get_name(),
        )
        return paramiko.AUTH_FAILED

    # --- Shell / PTY / exec -------------------------------------------------
    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        self.term = term.decode() if isinstance(term, bytes) else str(term)
        return True

    def check_channel_shell_request(self, channel) -> bool:
        # Signal the session handler to start the emulated interactive shell.
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        cmd = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else str(command)
        self.exec_commands.append(cmd)
        self._record.commands.append(
            CommandRecord(timestamp=utc_now_iso(), command=cmd, command_type="exec")
        )
        logger.info("exec session=%s cmd=%r", self._record.session_id, cmd)
        # Returning True lets the session handler send fake output then close.
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True
