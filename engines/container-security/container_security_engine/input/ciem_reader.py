"""
CIEM DB Reader for Container Security Engine.

Reads container-related events from the threat_engine_ciem database,
including CloudTrail events for EKS/ECS/ECR and K8s audit events.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# CloudTrail event sources for container services
CONTAINER_EVENT_SOURCES = (
    "eks.amazonaws.com",
    "ecs.amazonaws.com",
    "ecr.amazonaws.com",
)

# K8s audit event name patterns
K8S_AUDIT_EVENT_PATTERNS = (
    "CreatePod", "DeletePod", "ExecPod",
    "CreateDeployment", "DeleteDeployment",
    "CreateNamespace", "DeleteNamespace",
    "CreateServiceAccount", "CreateClusterRoleBinding",
    "CreateRole", "CreateRoleBinding",
)


def _get_ciem_conn():
    """Get connection to the CIEM database."""
    return psycopg2.connect(
        host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
        user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CIEM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class ContainerCIEMReader:
    """Reads container-related events from CIEM DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_ciem_conn()

    def load_container_events(
        self,
        tenant_id: str,
        account_id: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Load container-related CloudTrail events from CIEM DB.

        Tries normalized_events first, falls back to raw_events if the
        normalized table does not exist.

        Args:
            tenant_id: Tenant identifier.
            account_id: Cloud account identifier.
            days: Number of days of events to load (default 30).

        Returns:
            List of event dicts for container services.
        """
        self._ensure_conn()

        # Try normalized_events first
        for table in ("normalized_events", "raw_events"):
            try:
                with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(f"""
                        SELECT
                            event_id, event_time, event_source, event_name,
                            user_identity, source_ip, user_agent,
                            request_parameters, response_elements,
                            resources, account_id, region
                        FROM {table}
                        WHERE tenant_id = %s
                          AND account_id = %s
                          AND event_source = ANY(%s)
                          AND event_time >= NOW() - INTERVAL '%s days'
                        ORDER BY event_time DESC
                    """, (tenant_id, account_id, list(CONTAINER_EVENT_SOURCES), days))
                    rows = cur.fetchall()
                    logger.info(
                        f"CIEM: loaded {len(rows)} container events from {table} "
                        f"for account {account_id} (last {days} days)"
                    )
                    return [dict(r) for r in rows]
            except psycopg2.errors.UndefinedTable:
                self.conn.rollback()
                logger.warning(f"CIEM table {table} does not exist, trying fallback")
                continue
            except Exception as e:
                self.conn.rollback()
                logger.error(f"Failed to load container events from {table}: {e}", exc_info=True)
                return []

        logger.warning("CIEM: no event tables available for container events")
        return []

    def load_k8s_audit_events(
        self,
        tenant_id: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Load K8s audit events from CIEM DB.

        Searches for events whose event_name matches known K8s audit
        patterns (e.g., CreatePod, ExecPod, CreateClusterRoleBinding).

        Args:
            tenant_id: Tenant identifier.
            days: Number of days of events to load (default 30).

        Returns:
            List of K8s audit event dicts.
        """
        self._ensure_conn()

        # Build OR pattern for K8s event names
        event_patterns = list(K8S_AUDIT_EVENT_PATTERNS)

        for table in ("normalized_events", "raw_events"):
            try:
                with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(f"""
                        SELECT
                            event_id, event_time, event_source, event_name,
                            user_identity, source_ip, user_agent,
                            request_parameters, response_elements,
                            resources, account_id, region
                        FROM {table}
                        WHERE tenant_id = %s
                          AND event_name = ANY(%s)
                          AND event_time >= NOW() - INTERVAL '%s days'
                        ORDER BY event_time DESC
                    """, (tenant_id, event_patterns, days))
                    rows = cur.fetchall()
                    logger.info(
                        f"CIEM: loaded {len(rows)} K8s audit events from {table} "
                        f"(last {days} days)"
                    )
                    return [dict(r) for r in rows]
            except psycopg2.errors.UndefinedTable:
                self.conn.rollback()
                logger.warning(f"CIEM table {table} does not exist, trying fallback")
                continue
            except Exception as e:
                self.conn.rollback()
                logger.error(f"Failed to load K8s audit events from {table}: {e}", exc_info=True)
                return []

        logger.warning("CIEM: no event tables available for K8s audit events")
        return []

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
