"""
K8s Audit Log Processor — Task 0.2.6 [Seq 18 | BD]

Queries K8s audit logs from CloudWatch (EKS control plane audit), parses and
normalizes them, and writes to cloudtrail_events table (source_type='k8s_audit').

Input:  CloudWatch log group name (e.g., /aws/eks/cluster_name/cluster)
Output: cloudtrail_events table (source_type='k8s_audit')

Dependencies:
  - Task 0.2.1 (log_collector_schema.sql)
  - EKS audit logging must be enabled (pre-requisite)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import boto3

logger = logging.getLogger("log_collector.processors.k8s_audit")


class K8sAuditProcessor:
    """Queries and processes K8s audit logs from CloudWatch.

    Args:
        pool: asyncpg connection pool for threat_engine_logs.
        logs_client: boto3 CloudWatch Logs client (optional).
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        logs_client: Optional[Any] = None,
    ) -> None:
        self._pool = pool
        self._logs = logs_client or boto3.client("logs")

    async def process(
        self,
        log_group_name: str,
        cluster_name: str = "",
        lookback_hours: int = 24,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process K8s audit logs from a CloudWatch log group.

        Args:
            log_group_name: CloudWatch log group (e.g., /aws/eks/cluster/cluster).
            cluster_name: EKS cluster name for context.
            lookback_hours: How far back to query (default 24h).
            customer_id: Customer identifier.
            tenant_id: Tenant identifier.

        Returns:
            Summary dict with rows_inserted and rows_skipped.
        """
        logger.info("Processing K8s audit logs: log_group=%s cluster=%s lookback=%dh",
                     log_group_name, cluster_name, lookback_hours)

        now = datetime.now(timezone.utc)
        start_time = int((now - timedelta(hours=lookback_hours)).timestamp() * 1000)

        events = self._fetch_log_events(log_group_name, start_time)

        if not events:
            logger.warning("No K8s audit events found in %s", log_group_name)
            return {"rows_inserted": 0, "rows_skipped": 0}

        rows_inserted = 0
        rows_skipped = 0
        batch: List[Tuple] = []

        for event in events:
            message = event.get("message", "")
            try:
                audit_event = json.loads(message)
                row = self._normalize_event(
                    audit_event, cluster_name, customer_id, tenant_id, log_group_name
                )
                batch.append(row)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.warning("Skipping malformed K8s audit event: %s", exc)
                rows_skipped += 1

        if batch:
            rows_inserted = await self._bulk_insert(batch)

        logger.info(
            "Completed K8s audit log processing: inserted=%d skipped=%d",
            rows_inserted, rows_skipped,
        )
        return {"rows_inserted": rows_inserted, "rows_skipped": rows_skipped}

    def _fetch_log_events(self, log_group_name: str, start_time_ms: int) -> List[Dict]:
        """Fetch log events from CloudWatch, handling pagination."""
        all_events: List[Dict] = []
        params: Dict[str, Any] = {
            "logGroupName": log_group_name,
            "startTime": start_time_ms,
            "limit": 10000,
        }

        while True:
            try:
                response = self._logs.filter_log_events(**params)
            except Exception as exc:
                logger.error("Failed to fetch K8s audit logs from %s: %s", log_group_name, exc)
                break

            all_events.extend(response.get("events", []))

            next_token = response.get("nextToken")
            if not next_token:
                break
            params["nextToken"] = next_token

            if len(all_events) >= 100000:
                logger.warning("Hit 100k event limit for %s", log_group_name)
                break

        return all_events

    def _normalize_event(
        self,
        audit: Dict[str, Any],
        cluster_name: str,
        customer_id: Optional[str],
        tenant_id: Optional[str],
        source_file: str,
    ) -> Tuple:
        """Normalize a K8s audit event into a cloudtrail_events row.

        K8s audit format:
            {
                "level": "Metadata|Request|RequestResponse",
                "timestamp": "2024-01-01T00:00:00Z",
                "verb": "create|get|list|watch|delete|patch|update",
                "user": {"username": "...", "groups": [...]},
                "objectRef": {"resource": "pods", "name": "...", "namespace": "..."},
                "requestObject": {...},
                "responseObject": {...},
                "annotations": {...}
            }
        """
        # Parse timestamp
        ts_str = audit.get("stageTimestamp") or audit.get("timestamp", "")
        try:
            event_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        # Extract user identity
        user = audit.get("user", {})
        user_identity = {
            "username": user.get("username", ""),
            "groups": user.get("groups", []),
            "uid": user.get("uid", ""),
            "cluster_name": cluster_name,
        }

        # Extract resource info from objectRef
        obj_ref = audit.get("objectRef", {})
        resource_type = obj_ref.get("resource", "")  # e.g., 'pods', 'clusterroles'
        resource_name = obj_ref.get("name", "")
        resource_namespace = obj_ref.get("namespace", "")
        resource_id = f"{resource_namespace}/{resource_name}" if resource_namespace else resource_name

        # Source IP
        source_ips = audit.get("sourceIPs", [])
        source_ip = source_ips[0] if source_ips else None

        # Error info from responseStatus
        response_status = audit.get("responseStatus", {})
        error_code = None
        error_message = None
        status_code = response_status.get("code", 200)
        if status_code and int(status_code) >= 400:
            error_code = str(status_code)
            error_message = response_status.get("message", "")

        return (
            "k8s_audit",                                # source_type
            customer_id,                                # customer_id
            tenant_id,                                  # tenant_id
            event_time,                                 # event_time
            audit.get("verb", ""),                      # event_name (K8s verb)
            "kubernetes",                               # event_source
            json.dumps(user_identity),                  # user_identity (JSONB)
            resource_type,                              # resource_type (K8s kind)
            resource_id,                                # resource_id
            json.dumps(audit.get("requestObject") or {}),   # request_parameters
            json.dumps(audit.get("responseObject") or {}),  # response_elements
            error_code,                                 # error_code
            error_message,                              # error_message
            source_ip,                                  # source_ip (INET)
            audit.get("userAgent"),                     # user_agent
            None,                                       # region (N/A for K8s)
            json.dumps(audit),                          # raw_fields (full event)
            source_file,                                # source_file
        )

    async def _bulk_insert(self, rows: List[Tuple]) -> int:
        """Bulk insert normalized K8s audit events into cloudtrail_events."""
        sql = """
            INSERT INTO cloudtrail_events
                (source_type, customer_id, tenant_id, event_time,
                 event_name, event_source, user_identity,
                 resource_type, resource_id,
                 request_parameters, response_elements,
                 error_code, error_message,
                 source_ip, user_agent, region,
                 raw_fields, source_file)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9,
                 $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16, $17::jsonb, $18)
        """
        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

        return len(rows)
