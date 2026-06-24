"""Handles a single attacker connection end-to-end.

Responsibilities:
  * Negotiate SSH over the accepted socket using Paramiko's Transport.
  * Drive the fake authentication + emulated shell.
  * Capture every command the attacker types (logged, never executed).
  * Build the final `AttackRecord` and hand it to the capture sink.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Tuple

import paramiko

from .capture import AttackRecord, CaptureSink, CommandRecord, utc_now_iso
from .config import HoneypotConfig
from .ssh_server import HoneypotServer

logger = logging.getLogger("sentinelssh.session")

# Minimal fake filesystem responses so the shell feels real for a few commands.
_FAKE_RESPONSES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "uname": "Linux",
    "uname -a": "Linux srv01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "snap",
    "ls -la": "total 28\ndrwx------  4 root root 4096 Jan  1 00:00 .\ndrwxr-xr-x 19 root root 4096 Jan  1 00:00 ..",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
}


class SessionHandler:
    """Processes one inbound connection in its own thread."""

    def __init__(
        self,
        client_sock: socket.socket,
        addr: Tuple[str, int],
        config: HoneypotConfig,
        host_key: paramiko.PKey,
        sink: CaptureSink,
    ) -> None:
        self._sock = client_sock
        self._addr = addr
        self._config = config
        self._host_key = host_key
        self._sink = sink

    def handle(self) -> None:
        src_ip, src_port = self._addr[0], self._addr[1]
        start = time.monotonic()
        record = AttackRecord(
            session_id=_rand_id(),
            timestamp=utc_now_iso(),
            source_ip=src_ip,
            source_port=src_port,
        )
        transport: paramiko.Transport | None = None
        try:
            transport = paramiko.Transport(self._sock)
            transport.local_version = self._config.ssh_banner
            transport.add_server_key(self._host_key)

            server = HoneypotServer(record, self._config.max_auth_attempts)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                logger.info("ssh negotiation failed src=%s", src_ip)
                return

            # Capture the client's announced SSH version (e.g. attacker tooling).
            record.ssh_version = getattr(transport, "remote_version", None)
            if not record.session_id:
                record.session_id = _rand_id()

            channel = transport.accept(self._config.auth_timeout)
            if channel is None:
                logger.info("no channel opened src=%s session=%s", src_ip, record.session_id)
                return

            # Non-interactive exec requests are captured by the server interface.
            if server.exec_commands:
                self._handle_exec(channel, server.exec_commands)
            else:
                # Wait briefly for an interactive shell request.
                server.shell_event.wait(self._config.auth_timeout)
                if server.shell_event.is_set():
                    self._fake_shell(channel, record)
            channel.close()
        except (EOFError, ConnectionResetError, OSError) as exc:
            logger.debug("connection closed src=%s err=%s", src_ip, exc)
        except Exception:  # noqa: BLE001 - never let one session crash the server
            logger.exception("unhandled session error src=%s", src_ip)
        finally:
            record.duration = round(time.monotonic() - start, 3)
            if not record.session_id:
                record.session_id = _rand_id()
            self._sink.write(record)
            if transport is not None:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass
            try:
                self._sock.close()
            except Exception:  # noqa: BLE001
                pass

    # --- emulated interactions ---------------------------------------------
    def _handle_exec(self, channel: paramiko.Channel, commands: list[str]) -> None:
        """Respond to a non-interactive `ssh host <cmd>` with fake output."""
        for cmd in commands:
            output = _FAKE_RESPONSES.get(cmd.strip(), "")
            if output:
                channel.sendall((output + "\n").encode())
        channel.send_exit_status(0)

    def _fake_shell(self, channel: paramiko.Channel, record: AttackRecord) -> None:
        """Emulate an interactive shell, logging every command, executing none."""
        hostname = self._config.fake_hostname
        prompt = f"root@{hostname}:~# "
        channel.sendall(b"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")
        channel.sendall(prompt.encode())

        buffer = ""
        deadline = time.monotonic() + self._config.session_timeout
        while time.monotonic() < deadline:
            if len(record.commands) >= self._config.max_commands:
                break
            try:
                data = channel.recv(1024)
            except socket.timeout:
                continue
            if not data:
                break
            text = data.decode("utf-8", errors="replace")
            for ch in text:
                if ch in ("\r", "\n"):
                    channel.sendall(b"\r\n")
                    cmd = buffer.strip()
                    buffer = ""
                    if cmd:
                        record.commands.append(
                            CommandRecord(
                                timestamp=utc_now_iso(), command=cmd, command_type="shell"
                            )
                        )
                        logger.info("shell session=%s cmd=%r", record.session_id, cmd)
                        if cmd in ("exit", "logout", "quit"):
                            channel.sendall(b"logout\r\n")
                            return
                        channel.sendall(self._respond(cmd))
                    channel.sendall(prompt.encode())
                elif ch == "\x7f":  # backspace
                    if buffer:
                        buffer = buffer[:-1]
                        channel.sendall(b"\b \b")
                elif ch == "\x03":  # Ctrl-C
                    buffer = ""
                    channel.sendall(b"^C\r\n" + prompt.encode())
                else:
                    buffer += ch
                    channel.sendall(ch.encode())  # local echo

    @staticmethod
    def _respond(cmd: str) -> bytes:
        """Return believable but harmless output. No command is ever executed."""
        if cmd in _FAKE_RESPONSES:
            return (_FAKE_RESPONSES[cmd] + "\r\n").encode()
        first = cmd.split(" ", 1)[0]
        return f"-bash: {first}: command not found\r\n".encode()


def _rand_id() -> str:
    import secrets

    return secrets.token_hex(16)
