"""
virtualization category scanner — stub.
Implement connect()/discover()/disconnect() per sprint.
"""
from __future__ import annotations
import logging
from typing import List
from common.models.connector_interface import TechScanner, TechFinding, AuthenticationError
from executor.yaml_executor import TechYAMLExecutor

logger = logging.getLogger(__name__)


class VirtualizationScanner(TechScanner):
    """Scanner for category: virtualization"""

    async def connect(self) -> None:
        """TODO Sprint: implement connection for virtualization tech_type={self.tech_type}"""
        logger.info(f"[virtualization] connect host={self.host} tech_type={self.tech_type}")

    async def discover(self) -> List[TechFinding]:
        """Load YAML queries and execute them against the connected virtualization target."""
        executor = TechYAMLExecutor(
            tech_category=self.tech_category,
            tech_type=self.tech_type,
        ).load()
        findings: List[TechFinding] = []
        for query in executor.queries:
            discovery_id = query.get("discovery_id", "unknown")
            resource_uid = f"{self.host}:{discovery_id}"
            emit_item     = query.get("emit", {}).get("item", {})
            resource_type = emit_item.get("resource_type", f"{self.tech_type}.config")
            # TODO Sprint: dispatch to real connector (psycopg2 / paramiko / REST API etc.)
            raw_data = {"stub": True, "discovery_id": discovery_id, "host": self.host}
            findings.append(self._build_finding(
                discovery_id=discovery_id,
                resource_uid=resource_uid,
                resource_type=resource_type,
                raw_data=raw_data,
            ))
        return findings

    async def disconnect(self) -> None:
        logger.info(f"[virtualization] disconnect host={self.host}")
