"""
SSH connector for Linux/OS category.
Uses paramiko with StrictHostKeyChecking (RejectPolicy) for security.
Sprint 2 integrates this into the LinuxScanner.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class SSHConnector:
    """Wraps paramiko to execute commands on a remote Linux host."""

    def __init__(self, credential: Dict[str, Any]) -> None:
        self.host     = credential["host"]
        self.port     = int(credential.get("port", 22))
        self.username = credential.get("username", "root")
        self.password = credential.get("password")
        self.ssh_key  = credential.get("ssh_private_key")
        self.sudo     = bool(credential.get("sudo_required", False))
        self._client: Optional[Any] = None

    def connect(self) -> None:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())  # security: no auto-accept
        connect_kwargs: Dict[str, Any] = {
            "hostname": self.host,
            "port":     self.port,
            "username": self.username,
            "timeout":  10,
        }
        if self.ssh_key:
            import io
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(self.ssh_key))
            connect_kwargs["pkey"] = pkey
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise ValueError("SSH connector requires either ssh_private_key or password")

        client.connect(**connect_kwargs)
        self._client = client
        logger.info(f"SSH connected to {self.host}:{self.port}")

    def run(self, command: str, timeout: int = 10) -> Tuple[str, str, int]:
        """Execute a command. Returns (stdout, stderr, exit_code)."""
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")
        if self.sudo and not command.startswith("sudo "):
            command = f"sudo {command}"
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return stdout.read().decode(), stderr.read().decode(), exit_code

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
