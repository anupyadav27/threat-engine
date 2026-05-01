"""CIEM reader for Container Security Engine — EKS/ECS/ECR CloudTrail events."""

import logging
from typing import Any, Dict, List

import psycopg2

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_ciem_conn
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

CONTAINER_EVENT_SOURCES = (
    "eks.amazonaws.com",
    "ecs.amazonaws.com",
    "ecr.amazonaws.com",
)

K8S_AUDIT_EVENT_PATTERNS = (
    "CreatePod", "DeletePod", "ExecPod",
    "CreateDeployment", "DeleteDeployment",
    "CreateNamespace", "DeleteNamespace",
    "CreateServiceAccount", "CreateClusterRoleBinding",
    "CreateRole", "CreateRoleBinding",
)


class ContainerCIEMReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_ciem_conn)

    def load_container_events(
        self,
        tenant_id: str,
        account_id: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        self._ensure_conn()
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
                    logger.info("CIEM: loaded %d container events from %s (last %d days)", len(rows), table, days)
                    return [dict(r) for r in rows]
            except psycopg2.errors.UndefinedTable:
                if self.conn and not self.conn.closed:
                    self.conn.rollback()
                logger.warning("CIEM table %s does not exist, trying fallback", table)
                continue
            except Exception as e:
                if self.conn and not self.conn.closed:
                    self.conn.rollback()
                logger.error("Failed to load container events from %s: %s", table, e)
                return []
        logger.warning("CIEM: no event tables available for container events")
        return []

    def load_k8s_audit_events(
        self,
        tenant_id: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        self._ensure_conn()
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
                    """, (tenant_id, list(K8S_AUDIT_EVENT_PATTERNS), days))
                    rows = cur.fetchall()
                    logger.info("CIEM: loaded %d K8s audit events from %s (last %d days)", len(rows), table, days)
                    return [dict(r) for r in rows]
            except psycopg2.errors.UndefinedTable:
                if self.conn and not self.conn.closed:
                    self.conn.rollback()
                logger.warning("CIEM table %s does not exist, trying fallback", table)
                continue
            except Exception as e:
                if self.conn and not self.conn.closed:
                    self.conn.rollback()
                logger.error("Failed to load K8s audit events from %s: %s", table, e)
                return []
        logger.warning("CIEM: no event tables available for K8s audit events")
        return []
