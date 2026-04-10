"""
Check DB Reader for Container Security Engine.

Reads container-related check_findings joined with rule_metadata
from the threat_engine_check database.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Container services whose check rules are relevant
CONTAINER_SERVICES = (
    "eks", "ecs", "ecr", "fargate", "lambda",
)


def _get_check_conn():
    """Get connection to the Check database."""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class ContainerCheckReader:
    """Reads container-related findings from Check DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_check_conn()

    def load_container_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load check findings for container services.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.

        Returns:
            List of check finding dicts for container services.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        cf.scan_run_id, cf.rule_id, cf.service,
                        cf.resource_uid, cf.resource_type, cf.resource_id,
                        cf.region, cf.account_id, cf.provider,
                        cf.status, cf.checked_fields, cf.actual_values,
                        cf.finding_data
                    FROM check_findings cf
                    WHERE cf.scan_run_id = %s
                      AND cf.tenant_id = %s
                      AND cf.service = ANY(%s)
                """, (scan_run_id, tenant_id, list(CONTAINER_SERVICES)))
                rows = cur.fetchall()
                logger.info(f"Check: loaded {len(rows)} container service findings for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load container check findings: {e}", exc_info=True)
            return []

    def load_rule_metadata(
        self,
        rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Load rule_metadata for severity and compliance framework mapping.

        Args:
            rule_ids: Specific rule IDs to load. If None, loads all
                      rules for container services.

        Returns:
            Dict mapping rule_id to metadata dict.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                if rule_ids:
                    cur.execute("""
                        SELECT rule_id, service, severity, title, description,
                               remediation, data_security, compliance_frameworks
                        FROM rule_metadata
                        WHERE rule_id = ANY(%s)
                    """, (rule_ids,))
                else:
                    cur.execute("""
                        SELECT rule_id, service, severity, title, description,
                               remediation, data_security, compliance_frameworks
                        FROM rule_metadata
                        WHERE service = ANY(%s)
                    """, (list(CONTAINER_SERVICES),))
                rows = cur.fetchall()
                return {r["rule_id"]: dict(r) for r in rows}
        except Exception as e:
            logger.error(f"Failed to load rule metadata: {e}", exc_info=True)
            return {}

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
