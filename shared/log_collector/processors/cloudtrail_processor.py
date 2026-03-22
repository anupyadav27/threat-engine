"""
CloudTrail Processor — Task 0.2.4 [Seq 16 | BD]

Downloads CloudTrail event files from S3, parses the JSON events, normalizes
the records, and writes them to the cloudtrail_events table.

Input:  S3 object key (CloudTrail multi-file delivery, typically .json.gz)
Output: cloudtrail_events table (source_type='cloudtrail')

Dependencies:
  - Task 0.2.1 (log_collector_schema.sql)
  - Task 0.2.2 (log_source_registry — know which S3 bucket)
"""

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import boto3

logger = logging.getLogger("log_collector.processors.cloudtrail")


class CloudTrailProcessor:
    """Downloads, parses, and stores CloudTrail events from S3.

    Args:
        pool: asyncpg connection pool for threat_engine_logs.
        s3_client: boto3 S3 client (optional — created if not provided).
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        s3_client: Optional[Any] = None,
    ) -> None:
        self._pool = pool
        self._s3 = s3_client or boto3.client("s3")

    async def process(
        self,
        bucket: str,
        key: str,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process a single CloudTrail event file from S3.

        Args:
            bucket: S3 bucket name.
            key: S3 object key (.json.gz).
            customer_id: Customer identifier for multi-tenancy.
            tenant_id: Tenant identifier for multi-tenancy.

        Returns:
            Summary dict with rows_inserted and rows_skipped.
        """
        logger.info("Processing CloudTrail file: s3://%s/%s", bucket, key)

        # 1. Download from S3
        raw_bytes = self._download_from_s3(bucket, key)

        # 2. Decompress if gzipped
        if key.endswith(".gz"):
            raw_bytes = gzip.decompress(raw_bytes)

        # 3. Parse JSON
        try:
            data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse CloudTrail JSON from s3://%s/%s: %s", bucket, key, exc)
            return {"rows_inserted": 0, "rows_skipped": 1}

        events = data.get("Records", [])
        if not events:
            logger.warning("No Records found in CloudTrail file s3://%s/%s", bucket, key)
            return {"rows_inserted": 0, "rows_skipped": 0}

        # 4. Normalize and insert
        rows_inserted = 0
        rows_skipped = 0
        batch: List[Tuple] = []

        for event in events:
            try:
                row = self._normalize_event(event, customer_id, tenant_id, f"s3://{bucket}/{key}")
                batch.append(row)
            except Exception as exc:
                logger.warning("Skipping malformed CloudTrail event: %s", exc)
                rows_skipped += 1

        if batch:
            rows_inserted = await self._bulk_insert(batch)

        logger.info(
            "Completed CloudTrail processing: inserted=%d skipped=%d",
            rows_inserted, rows_skipped,
        )
        return {"rows_inserted": rows_inserted, "rows_skipped": rows_skipped}

    def _download_from_s3(self, bucket: str, key: str) -> bytes:
        """Download an S3 object and return raw bytes."""
        response = self._s3.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    def _normalize_event(
        self,
        event: Dict[str, Any],
        customer_id: Optional[str],
        tenant_id: Optional[str],
        source_file: str,
    ) -> Tuple:
        """Normalize a single CloudTrail event into a row tuple.

        Args:
            event: Raw CloudTrail event dict.
            customer_id: Customer identifier.
            tenant_id: Tenant identifier.
            source_file: S3 key for provenance tracking.

        Returns:
            Tuple of values matching the cloudtrail_events INSERT columns.

        Raises:
            KeyError: If required fields are missing.
        """
        # Parse event time
        event_time_str = event.get("eventTime", "")
        try:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        # Extract user identity
        user_identity = event.get("userIdentity", {})

        # Determine resource type and ID from resources array
        resources = event.get("resources", [])
        resource_type = None
        resource_id = None
        if resources:
            first_resource = resources[0]
            resource_type = first_resource.get("type")
            resource_id = first_resource.get("ARN")

        # Source IP
        source_ip = event.get("sourceIPAddress")
        # Some CloudTrail events have service names instead of IPs
        if source_ip and not _is_ip_address(source_ip):
            source_ip = None

        return (
            "cloudtrail",                                    # source_type
            customer_id,                                     # customer_id
            tenant_id,                                       # tenant_id
            event_time,                                      # event_time
            event.get("eventName", ""),                      # event_name
            event.get("eventSource", ""),                    # event_source
            json.dumps(user_identity),                       # user_identity (JSONB)
            resource_type,                                   # resource_type
            resource_id,                                     # resource_id
            json.dumps(event.get("requestParameters") or {}),  # request_parameters
            json.dumps(event.get("responseElements") or {}),   # response_elements
            event.get("errorCode"),                          # error_code
            event.get("errorMessage"),                       # error_message
            source_ip,                                       # source_ip (INET)
            event.get("userAgent"),                          # user_agent
            event.get("awsRegion"),                          # region
            json.dumps(event),                               # raw_fields (full event)
            source_file,                                     # source_file
        )

    async def _bulk_insert(self, rows: List[Tuple]) -> int:
        """Bulk insert normalized CloudTrail events.

        Returns:
            Number of rows inserted.
        """
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


def _is_ip_address(value: str) -> bool:
    """Check if a string looks like an IP address (v4 or v6)."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
