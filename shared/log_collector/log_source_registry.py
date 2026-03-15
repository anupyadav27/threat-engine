"""
Log Source Registry — Task 0.2.2 [Seq 14 | BD]

Tracks which log sources are configured (S3 buckets, CloudWatch log groups) and
their collection schedules. Processors read from this registry to know where to
fetch data and when to refresh.

Tables used:
  - log_sources (read/write)

Dependencies:
  - Task 0.2.1 (log_collector_schema.sql must be applied)
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg

# Add parent paths for shared imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

logger = logging.getLogger("log_collector.log_source_registry")

# ---------------------------------------------------------------------------
# Valid source types
# ---------------------------------------------------------------------------
VALID_SOURCE_TYPES = frozenset({"vpc_flow", "cloudtrail", "api_access", "k8s_audit"})


# ---------------------------------------------------------------------------
# Database connection helper
# ---------------------------------------------------------------------------
async def _get_pool(
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> asyncpg.Pool:
    """Create an asyncpg connection pool for the log collector database.

    Falls back to environment variables if arguments are not provided.
    """
    return await asyncpg.create_pool(
        host=host or os.environ.get("LOG_COLLECTOR_DB_HOST", "localhost"),
        port=port or int(os.environ.get("LOG_COLLECTOR_DB_PORT", "5432")),
        database=database or os.environ.get("LOG_COLLECTOR_DB_NAME", "threat_engine_logs"),
        user=user or os.environ.get("LOG_COLLECTOR_DB_USER", "postgres"),
        password=password or os.environ.get("LOG_COLLECTOR_DB_PASSWORD", ""),
        min_size=1,
        max_size=5,
    )


# ---------------------------------------------------------------------------
# LogSourceRegistry
# ---------------------------------------------------------------------------
class LogSourceRegistry:
    """Manages the log_sources table — registers, updates, and queries sources.

    Usage::

        registry = LogSourceRegistry(pool)
        await registry.register_source(
            source_type="vpc_flow",
            source_name="prod-vpc-flow-logs",
            source_config={"s3_bucket": "my-bucket", "s3_prefix": "AWSLogs/.../VPCFlowLogs/", "region": "us-east-1"},
            customer_id="cust-123",
            tenant_id="tenant-456",
        )
        sources = await registry.get_active_sources("vpc_flow")
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    # ------------------------------------------------------------------
    # Register / upsert a log source
    # ------------------------------------------------------------------
    async def register_source(
        self,
        source_type: str,
        source_name: str,
        source_config: Dict[str, Any],
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        collection_schedule_minutes: int = 60,
        is_active: bool = True,
    ) -> Dict[str, Any]:
        """Register or update a log source in the registry.

        Args:
            source_type: One of 'vpc_flow', 'cloudtrail', 'api_access', 'k8s_audit'.
            source_name: Human-readable name (e.g., 'prod-vpc-flow-logs').
            source_config: Configuration JSONB — keys vary by source_type.
            customer_id: Optional customer identifier for multi-tenancy.
            tenant_id: Optional tenant identifier for multi-tenancy.
            collection_schedule_minutes: How often to poll (default 60).
            is_active: Whether the source is enabled.

        Returns:
            The upserted row as a dict.

        Raises:
            ValueError: If source_type is not recognised.
        """
        if source_type not in VALID_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type '{source_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_SOURCE_TYPES))}"
            )

        sql = """
            INSERT INTO log_sources
                (source_type, source_name, source_config, customer_id, tenant_id,
                 collection_schedule_minutes, is_active, updated_at)
            VALUES
                ($1, $2, $3::jsonb, $4, $5, $6, $7, NOW())
            ON CONFLICT (source_type, source_name, customer_id, tenant_id) DO UPDATE SET
                source_config = EXCLUDED.source_config,
                collection_schedule_minutes = EXCLUDED.collection_schedule_minutes,
                is_active = EXCLUDED.is_active,
                updated_at = NOW()
            RETURNING *
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                source_type,
                source_name,
                json.dumps(source_config),
                customer_id,
                tenant_id,
                collection_schedule_minutes,
                is_active,
            )
            result = dict(row) if row else {}
            logger.info(
                "Registered log source: type=%s name=%s active=%s",
                source_type, source_name, is_active,
            )
            return result

    # ------------------------------------------------------------------
    # Query active sources
    # ------------------------------------------------------------------
    async def get_active_sources(
        self,
        source_type: Optional[str] = None,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return all active log sources, optionally filtered by type and tenant.

        Args:
            source_type: Filter by source type (optional).
            customer_id: Filter by customer (optional).
            tenant_id: Filter by tenant (optional).

        Returns:
            List of source dicts.
        """
        conditions = ["is_active = TRUE"]
        params: list = []
        idx = 1

        if source_type is not None:
            conditions.append(f"source_type = ${idx}")
            params.append(source_type)
            idx += 1
        if customer_id is not None:
            conditions.append(f"customer_id = ${idx}")
            params.append(customer_id)
            idx += 1
        if tenant_id is not None:
            conditions.append(f"tenant_id = ${idx}")
            params.append(tenant_id)
            idx += 1

        where = " AND ".join(conditions)
        sql = f"SELECT * FROM log_sources WHERE {where} ORDER BY source_type, source_name"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Update collection status after a processor run
    # ------------------------------------------------------------------
    async def update_collection_status(
        self,
        source_id: int,
        status: str,
        row_count: int = 0,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Update the last_collection_* fields on a log source after a run.

        Args:
            source_id: The log_sources.id value.
            status: 'success' or 'failed'.
            row_count: Number of rows processed.
            duration_ms: Processing time in milliseconds.
        """
        sql = """
            UPDATE log_sources SET
                last_collection_time   = NOW(),
                last_collection_status = $1,
                last_collection_row_count = $2,
                last_collection_duration_ms = $3,
                updated_at = NOW()
            WHERE id = $4
        """
        async with self._pool.acquire() as conn:
            await conn.execute(sql, status, row_count, duration_ms, source_id)
            logger.info(
                "Updated collection status: source_id=%d status=%s rows=%d",
                source_id, status, row_count,
            )

    # ------------------------------------------------------------------
    # Deactivate a source
    # ------------------------------------------------------------------
    async def deactivate_source(self, source_id: int) -> None:
        """Mark a log source as inactive (soft delete)."""
        sql = "UPDATE log_sources SET is_active = FALSE, updated_at = NOW() WHERE id = $1"
        async with self._pool.acquire() as conn:
            await conn.execute(sql, source_id)
            logger.info("Deactivated log source: source_id=%d", source_id)

    # ------------------------------------------------------------------
    # Get sources due for collection
    # ------------------------------------------------------------------
    async def get_sources_due_for_collection(
        self,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return active sources whose collection interval has elapsed.

        A source is due if:
          - last_collection_time is NULL (never collected), OR
          - NOW() - last_collection_time > collection_schedule_minutes
        """
        conditions = [
            "is_active = TRUE",
            """(
                last_collection_time IS NULL
                OR last_collection_time < NOW() - (collection_schedule_minutes || ' minutes')::interval
            )""",
        ]
        params: list = []
        idx = 1

        if customer_id is not None:
            conditions.append(f"customer_id = ${idx}")
            params.append(customer_id)
            idx += 1
        if tenant_id is not None:
            conditions.append(f"tenant_id = ${idx}")
            params.append(tenant_id)
            idx += 1

        where = " AND ".join(conditions)
        sql = f"SELECT * FROM log_sources WHERE {where} ORDER BY source_type, source_name"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Bootstrap — seed default sources from environment variables
# ---------------------------------------------------------------------------
async def bootstrap_sources_from_env(pool: asyncpg.Pool) -> int:
    """Read log source config from environment variables and register them.

    Environment variable pattern::

        LOG_SOURCE_VPC_FLOW_BUCKET      = "my-vpc-flow-bucket"
        LOG_SOURCE_VPC_FLOW_PREFIX      = "AWSLogs/123456789012/vpcflowlogs/"
        LOG_SOURCE_VPC_FLOW_REGION      = "us-east-1"

        LOG_SOURCE_CLOUDTRAIL_BUCKET    = "my-cloudtrail-bucket"
        LOG_SOURCE_CLOUDTRAIL_PREFIX    = "AWSLogs/123456789012/CloudTrail/"
        LOG_SOURCE_CLOUDTRAIL_REGION    = "us-east-1"

        LOG_SOURCE_API_ACCESS_LOG_GROUP = "/aws/apigateway/my-api"
        LOG_SOURCE_API_ACCESS_REGION    = "us-east-1"

        LOG_SOURCE_K8S_AUDIT_LOG_GROUP  = "/aws/eks/prod-cluster/cluster"
        LOG_SOURCE_K8S_AUDIT_CLUSTER    = "prod-cluster"
        LOG_SOURCE_K8S_AUDIT_REGION     = "us-east-1"

    Returns:
        Number of sources registered.
    """
    registry = LogSourceRegistry(pool)
    count = 0

    # --- VPC Flow Logs ---
    vpc_bucket = os.environ.get("LOG_SOURCE_VPC_FLOW_BUCKET")
    if vpc_bucket:
        await registry.register_source(
            source_type="vpc_flow",
            source_name="default-vpc-flow",
            source_config={
                "s3_bucket": vpc_bucket,
                "s3_prefix": os.environ.get("LOG_SOURCE_VPC_FLOW_PREFIX", ""),
                "region": os.environ.get("LOG_SOURCE_VPC_FLOW_REGION", "us-east-1"),
            },
            collection_schedule_minutes=int(
                os.environ.get("LOG_SOURCE_VPC_FLOW_SCHEDULE_MINUTES", "60")
            ),
        )
        count += 1
        logger.info("Bootstrapped VPC flow log source from env: bucket=%s", vpc_bucket)

    # --- CloudTrail ---
    ct_bucket = os.environ.get("LOG_SOURCE_CLOUDTRAIL_BUCKET")
    if ct_bucket:
        await registry.register_source(
            source_type="cloudtrail",
            source_name="default-cloudtrail",
            source_config={
                "s3_bucket": ct_bucket,
                "s3_prefix": os.environ.get("LOG_SOURCE_CLOUDTRAIL_PREFIX", ""),
                "region": os.environ.get("LOG_SOURCE_CLOUDTRAIL_REGION", "us-east-1"),
            },
            collection_schedule_minutes=int(
                os.environ.get("LOG_SOURCE_CLOUDTRAIL_SCHEDULE_MINUTES", "60")
            ),
        )
        count += 1
        logger.info("Bootstrapped CloudTrail source from env: bucket=%s", ct_bucket)

    # --- API Access Logs ---
    api_log_group = os.environ.get("LOG_SOURCE_API_ACCESS_LOG_GROUP")
    if api_log_group:
        await registry.register_source(
            source_type="api_access",
            source_name="default-api-access",
            source_config={
                "log_group_name": api_log_group,
                "region": os.environ.get("LOG_SOURCE_API_ACCESS_REGION", "us-east-1"),
            },
            collection_schedule_minutes=int(
                os.environ.get("LOG_SOURCE_API_ACCESS_SCHEDULE_MINUTES", "60")
            ),
        )
        count += 1
        logger.info("Bootstrapped API access log source from env: log_group=%s", api_log_group)

    # --- K8s Audit Logs ---
    k8s_log_group = os.environ.get("LOG_SOURCE_K8S_AUDIT_LOG_GROUP")
    if k8s_log_group:
        await registry.register_source(
            source_type="k8s_audit",
            source_name="default-k8s-audit",
            source_config={
                "log_group_name": k8s_log_group,
                "cluster_name": os.environ.get("LOG_SOURCE_K8S_AUDIT_CLUSTER", ""),
                "region": os.environ.get("LOG_SOURCE_K8S_AUDIT_REGION", "us-east-1"),
            },
            collection_schedule_minutes=int(
                os.environ.get("LOG_SOURCE_K8S_AUDIT_SCHEDULE_MINUTES", "60")
            ),
        )
        count += 1
        logger.info("Bootstrapped K8s audit log source from env: log_group=%s", k8s_log_group)

    logger.info("Bootstrap complete: %d sources registered", count)
    return count
