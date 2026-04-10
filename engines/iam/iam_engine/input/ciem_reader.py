"""
CIEM Data Reader — enriches IAM analysis with actual usage data from log_events.

Reads log_events (CloudTrail) to determine:
1. Which roles/users are actually used (vs just configured)
2. What operations each identity actually calls
3. Cross-account AssumeRole patterns
4. Last activity timestamp per identity

This turns IAM analysis from "what CAN they do" to "what DO they do".
"""

import os
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class CIEMReader:
    """Read actual IAM usage from log_events."""

    def __init__(self):
        self._conn = None

    def _get_conn(self):
        if self._conn and not self._conn.closed:
            return self._conn
        self._conn = psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )
        return self._conn

    def close(self):
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def get_identity_usage(self, tenant_id: str, days: int = 30) -> Dict[str, Dict]:
        """Get actual usage per IAM identity from CloudTrail events.

        Returns: {
            "arn:aws:iam::123:role/my-role": {
                "principal": "arn:...",
                "principal_type": "assumedrole",
                "total_api_calls": 500,
                "unique_operations": 15,
                "unique_services": 3,
                "operations": {"DescribeInstances": 100, "AssumeRole": 50, ...},
                "services": {"ec2": 200, "sts": 50, ...},
                "last_activity": "2026-03-27T15:00:00Z",
                "first_activity": "2026-03-25T10:00:00Z",
                "source_ips": ["10.0.1.5", "eks.amazonaws.com"],
                "is_service_role": true,
            }
        }
        """
        conn = self._get_conn()
        usage = {}

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        actor_principal,
                        actor_principal_type,
                        count(*) AS total_calls,
                        count(DISTINCT operation) AS unique_ops,
                        count(DISTINCT service) AS unique_services,
                        min(event_time) AS first_activity,
                        max(event_time) AS last_activity,
                        array_agg(DISTINCT actor_ip) FILTER (WHERE actor_ip IS NOT NULL AND actor_ip != '') AS source_ips
                    FROM log_events
                    WHERE tenant_id = %s
                    AND event_time > NOW() - INTERVAL '%s days'
                    AND actor_principal IS NOT NULL AND actor_principal != ''
                    GROUP BY actor_principal, actor_principal_type
                """, (tenant_id, days))

                for row in cur.fetchall():
                    principal = row["actor_principal"]
                    is_service = (
                        row["actor_principal_type"] in ("awsservice", "service")
                        or any(ip.endswith(".amazonaws.com") for ip in (row["source_ips"] or []))
                    )
                    usage[principal] = {
                        "principal": principal,
                        "principal_type": row["actor_principal_type"],
                        "total_api_calls": row["total_calls"],
                        "unique_operations": row["unique_ops"],
                        "unique_services": row["unique_services"],
                        "first_activity": row["first_activity"].isoformat() if row["first_activity"] else None,
                        "last_activity": row["last_activity"].isoformat() if row["last_activity"] else None,
                        "source_ips": row["source_ips"] or [],
                        "is_service_role": is_service,
                    }

                # Get per-identity operation breakdown (top 10 per identity)
                cur.execute("""
                    SELECT actor_principal, service, operation, count(*) AS cnt
                    FROM log_events
                    WHERE tenant_id = %s
                    AND event_time > NOW() - INTERVAL '%s days'
                    AND actor_principal IS NOT NULL AND actor_principal != ''
                    GROUP BY actor_principal, service, operation
                    ORDER BY actor_principal, cnt DESC
                """, (tenant_id, days))

                for row in cur.fetchall():
                    principal = row["actor_principal"]
                    if principal in usage:
                        usage[principal].setdefault("operations", {})[row["operation"]] = row["cnt"]
                        usage[principal].setdefault("services", {})[row["service"]] = (
                            usage[principal].get("services", {}).get(row["service"], 0) + row["cnt"]
                        )

        except Exception as exc:
            logger.warning(f"Failed to load identity usage: {exc}")

        logger.info(f"Loaded usage for {len(usage)} identities from log_events")
        return usage

    def get_cross_account_access(self, tenant_id: str, account_id: str, days: int = 30) -> List[Dict]:
        """Find cross-account AssumeRole events."""
        conn = self._get_conn()
        results = []

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT actor_principal, actor_account_id, actor_ip,
                           resource_uid, count(*) AS assume_count,
                           min(event_time) AS first_seen,
                           max(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s
                    AND operation = 'AssumeRole'
                    AND actor_account_id IS NOT NULL
                    AND actor_account_id != %s
                    AND actor_account_id != ''
                    AND event_time > NOW() - INTERVAL '%s days'
                    GROUP BY actor_principal, actor_account_id, actor_ip, resource_uid
                    ORDER BY assume_count DESC
                """, (tenant_id, account_id, days))
                results = [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"Failed to load cross-account access: {exc}")

        logger.info(f"Found {len(results)} cross-account access patterns")
        return results

    def get_ciem_findings_for_iam(self, tenant_id: str, scan_run_id: str = "") -> List[Dict]:
        """Get CIEM findings relevant to IAM (privilege changes, credential events)."""
        try:
            ciem_conn = psycopg2.connect(
                host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
                port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
                database=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
                user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
                password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                         os.getenv("DB_PASSWORD", ""))),
            )
            with ciem_conn.cursor(cursor_factory=RealDictCursor) as cur:
                scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
                params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

                cur.execute(f"""
                    SELECT finding_id, rule_id, severity, operation,
                           actor_principal, actor_principal_type,
                           resource_uid, resource_type, event_time,
                           title, action_category, primary_engine
                    FROM ciem_findings
                    WHERE tenant_id = %s {scan_filter}
                    AND (primary_engine IN ('ciem', 'ciem_engine')
                         OR service = 'iam' OR service = 'sts')
                    ORDER BY event_time DESC
                """, params)
                results = [dict(r) for r in cur.fetchall()]

            ciem_conn.close()
            logger.info(f"Loaded {len(results)} CIEM findings for IAM")
            return results
        except Exception as exc:
            logger.warning(f"Failed to load CIEM findings: {exc}")
            return []
