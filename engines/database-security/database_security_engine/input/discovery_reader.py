"""
Discovery DB Reader for Database Security Engine.

Reads database-related resources (RDS, DynamoDB, Redshift, ElastiCache,
Neptune, DocumentDB, OpenSearch, Timestream, Keyspaces, DAX) from
the discovery_findings table in threat_engine_discoveries.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Database service types to load from discovery_findings
DB_SERVICES = (
    "rds", "dynamodb", "redshift", "elasticache", "neptune",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
)


def _get_discoveries_conn():
    """Get connection to the Discoveries database."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class DiscoveryReader:
    """Reads database-related resources from Discovery DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_discoveries_conn()

    def load_all_db_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load all database-related resources grouped by service.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            account_id: Optional cloud account filter.

        Returns:
            Dict mapping service name to list of resource dicts.
        """
        result = {}
        for service in DB_SERVICES:
            resources = self.load_by_service(scan_run_id, tenant_id, service, account_id)
            if resources:
                result[service] = resources
        return result

    def load_by_service(
        self,
        scan_run_id: str,
        tenant_id: str,
        service: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load discovery_findings filtered by service.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            service: Service name (e.g., 'rds', 'dynamodb').
            account_id: Optional cloud account filter.

        Returns:
            List of resource dicts with emitted_fields extracted.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        resource_uid, resource_id, resource_type, service,
                        region, account_id, provider,
                        emitted_fields, raw_response,
                        config_hash, version, scan_timestamp
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND service = %s
                """
                params = [scan_run_id, tenant_id, service]

                if account_id:
                    sql += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(sql, params)
                rows = cur.fetchall()
                logger.info(f"Discovery: loaded {len(rows)} {service} resources for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load {service} discovery resources: {e}", exc_info=True)
            return []

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()

# Alias for backwards compatibility
DBDiscoveryReader = DiscoveryReader
