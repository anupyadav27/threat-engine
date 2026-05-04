"""
Linux category scanner — wraps SSHConnector + TechYAMLExecutor.
Supports tech_type: ubuntu, rhel, debian, suse, centos.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from common.models.connector_interface import AuthenticationError, TechFinding, TechScanner
from executor.yaml_executor import TechYAMLExecutor
from .connectors.ssh_connector import SSHConnector

logger = logging.getLogger(__name__)


def _parse_linux_audit_result(stdout: str) -> dict:
    """Extract PASS/FAIL from CIS benchmark script stdout sentinel lines."""
    if "** PASS **" in stdout:
        return {"status": "PASS", "severity": "info"}
    if "** FAIL **" in stdout:
        return {"status": "FAIL", "severity": "medium"}
    return {"status": "UNKNOWN", "severity": "low"}


class LinuxScanner(TechScanner):
    """SSH-based scanner for Linux tech types: ubuntu, rhel, debian, suse, centos."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._connector: Optional[SSHConnector] = None

    async def connect(self) -> None:
        connector = SSHConnector(self.credential)
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, connector.connect)
        except Exception as exc:
            logger.error("[linux] SSH connect failed host=%s type=%s", self.host, type(exc).__name__)
            raise AuthenticationError(f"SSH connection to {self.host} failed: {exc}") from exc
        self._connector = connector
        logger.info("[linux] connected host=%s tech_type=%s", self.host, self.tech_type)

    async def discover(self) -> List[TechFinding]:
        if not self._connector:
            raise RuntimeError("Call connect() before discover()")

        executor = TechYAMLExecutor(
            tech_category=self.tech_category,
            tech_type=self.tech_type,
        ).load()

        loop = asyncio.get_event_loop()
        findings: List[TechFinding] = []

        for entry in executor.queries:
            discovery_id = entry.get("discovery_id", "unknown")
            emit_item    = entry.get("emit", {}).get("item", {})
            resource_type = emit_item.get("resource_type", f"{self.tech_type}.config")

            try:
                results = await loop.run_in_executor(
                    None, executor.execute_entry, entry, self._connector, self.host
                )
                for result in results:
                    raw = dict(result.get("raw_data") or {})
                    resource_uid = result.get("resource_uid", f"{self.host}:{discovery_id}")
                    parsed = _parse_linux_audit_result(raw.get("stdout", ""))
                    raw.update(parsed)
                    findings.append(self._build_finding(
                        discovery_id=discovery_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        raw_data=raw,
                    ))
            except Exception as exc:
                logger.warning("[linux] discovery_id=%s error: %s", discovery_id, exc)
                findings.append(self._build_finding(
                    discovery_id=discovery_id,
                    resource_uid=f"{self.host}:{discovery_id}",
                    resource_type=resource_type,
                    raw_data={"error": str(exc)},
                    error_message=str(exc),
                ))

        logger.info(
            "[linux] discover complete host=%s tech_type=%s findings=%d",
            self.host, self.tech_type, len(findings),
        )
        return findings

    async def disconnect(self) -> None:
        if self._connector:
            self._connector.close()
            self._connector = None
        logger.info("[linux] disconnected host=%s", self.host)
