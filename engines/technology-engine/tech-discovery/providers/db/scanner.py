"""
DB category scanner — executes YAML-driven discovery via DB connectors.
Covers: postgres, mysql, mariadb, mssql, mongodb, oracle, cassandra, ibm_db2
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from common.models.connector_interface import (
    AuthenticationError,
    DiscoveryError,
    TechFinding,
    TechScanner,
)
from executor.yaml_executor import TechYAMLExecutor
from providers.db.connectors.db_connector import get_db_connector, BaseDBConnector

try:
    from engine_common.resource_id import host_to_resource_uid
except ImportError:
    from shared.common.resource_id import host_to_resource_uid

logger = logging.getLogger(__name__)


class DBScanner(TechScanner):
    """Scanner for the 'db' tech category."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._connector: BaseDBConnector | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        try:
            self._connector = get_db_connector(self.tech_type, self.credential)
            self._connector.connect()
            logger.info(
                "DB connected: tech_type=%s host=%s:%s",
                self.tech_type, self.host, self.port,
            )
        except Exception as exc:
            raise AuthenticationError(
                f"Cannot connect to {self.tech_type} at {self.host}: {exc}"
            ) from exc

    async def disconnect(self) -> None:
        if self._connector:
            self._connector.close()
            self._connector = None

    # ── discovery ─────────────────────────────────────────────────────────────

    async def discover(self) -> List[TechFinding]:
        if not self._connector:
            raise DiscoveryError("Not connected — call connect() first")

        try:
            executor = TechYAMLExecutor(
                tech_category=self.tech_category,
                tech_type=self.tech_type,
            ).load()
        except FileNotFoundError as exc:
            logger.warning("No discovery YAML for %s/%s: %s", self.tech_category, self.tech_type, exc)
            return []

        # Canonical resource_uid for this database — same value the cloud engine
        # stores in discovery_findings.resource_uid (DBInstanceArn for AWS RDS,
        # hostname for self-hosted / Azure / GCP).  All findings for the same
        # database share this uid so the compliance engine sees one asset, not one
        # per discovery check.
        canonical_uid = host_to_resource_uid(
            host=self.host,
            provider=self.tech_type,
            account_id=self.account_id,
        )

        findings: List[TechFinding] = []

        for entry in executor.queries:
            disc_id      = entry.get("discovery_id", "unknown")
            resource_type = entry.get("resource_type", f"{self.tech_type}.config")

            results = executor.execute_entry(
                entry=entry,
                connector=self._connector,
                host=self.host,
            )

            for item in results:
                raw_data  = item.get("raw_data", {})
                error_msg = raw_data.get("error") if "error" in raw_data else None

                finding = self._build_finding(
                    discovery_id  = disc_id,
                    resource_uid  = canonical_uid,
                    resource_type = resource_type,
                    raw_data      = raw_data,
                    error_message = error_msg,
                )
                findings.append(finding)
                logger.debug(
                    "discovery_id=%s resource_uid=%s rows=%d",
                    disc_id, resource_uid, len(raw_data) if isinstance(raw_data, list) else 1,
                )

        logger.info(
            "DB discovery complete: tech_type=%s findings=%d",
            self.tech_type, len(findings),
        )
        return findings
