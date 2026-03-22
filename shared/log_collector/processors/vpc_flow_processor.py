"""
VPC Flow Log Processor — Task 0.2.3 [Seq 15 | BD]

Downloads VPC flow log files from S3, decompresses and parses the space-separated
records, aggregates them into 5-minute windows, and writes results to log_events
and event_aggregations tables.

Input:  S3 object key from SQS event notification (gz compressed flow log file)
Output: log_events (raw parsed records), event_aggregations (5-min summaries)

Dependencies:
  - Task 0.2.1 (log_collector_schema.sql)
  - Task 0.2.2 (log_source_registry — know which S3 bucket to query)
"""

import gzip
import io
import logging
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import boto3

logger = logging.getLogger("log_collector.processors.vpc_flow")

# ---------------------------------------------------------------------------
# VPC Flow Log field positions (v2 default format)
# https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
# ---------------------------------------------------------------------------
FLOW_LOG_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]

PROTOCOL_MAP = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "58": "ICMPv6",
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_flow_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single VPC flow log line into a dict.

    Args:
        line: Space-separated flow log record.

    Returns:
        Parsed dict or None if the line is malformed or a header.
    """
    line = line.strip()
    if not line or line.startswith("version"):
        return None

    parts = line.split()
    if len(parts) < len(FLOW_LOG_FIELDS):
        logger.warning("Malformed flow log line (expected %d fields, got %d): %s",
                        len(FLOW_LOG_FIELDS), len(parts), line[:200])
        return None

    record: Dict[str, Any] = {}
    for i, field in enumerate(FLOW_LOG_FIELDS):
        val = parts[i]
        record[field] = val if val != "-" else None

    # Validate action field
    if record.get("action") not in ("ACCEPT", "REJECT", None):
        logger.warning("Invalid action '%s' in flow log line", record.get("action"))
        return None

    # Convert numeric fields
    try:
        record["srcport"] = int(record["srcport"]) if record["srcport"] else None
        record["dstport"] = int(record["dstport"]) if record["dstport"] else None
        record["packets"] = int(record["packets"]) if record["packets"] else 0
        record["bytes"] = int(record["bytes"]) if record["bytes"] else 0
        record["start"] = int(record["start"]) if record["start"] else None
        record["end"] = int(record["end"]) if record["end"] else None
    except (ValueError, TypeError) as exc:
        logger.warning("Failed to parse numeric field: %s — line: %s", exc, line[:200])
        return None

    # Map protocol number to name
    proto = record.get("protocol")
    record["protocol_name"] = PROTOCOL_MAP.get(proto, proto)

    return record


def _truncate_to_5min(ts: int) -> datetime:
    """Truncate a unix timestamp to the nearest 5-minute boundary."""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    minute = (dt.minute // 5) * 5
    return dt.replace(minute=minute, second=0, microsecond=0)


# ---------------------------------------------------------------------------
# Processor
# ---------------------------------------------------------------------------
class VPCFlowProcessor:
    """Downloads, parses, and stores VPC flow log records from S3.

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
        """Process a single VPC flow log file from S3.

        Args:
            bucket: S3 bucket name.
            key: S3 object key (typically .gz compressed).
            customer_id: Customer identifier for multi-tenancy.
            tenant_id: Tenant identifier for multi-tenancy.

        Returns:
            Summary dict with rows_inserted, rows_skipped, aggregation_rows.
        """
        logger.info("Processing VPC flow log: s3://%s/%s", bucket, key)

        # 1. Download from S3
        raw_bytes = self._download_from_s3(bucket, key)

        # 2. Decompress if gzipped
        if key.endswith(".gz"):
            raw_bytes = gzip.decompress(raw_bytes)

        # 3. Parse lines
        text = raw_bytes.decode("utf-8", errors="replace")
        lines = text.strip().split("\n")

        records: List[Dict[str, Any]] = []
        skipped = 0
        for line in lines:
            parsed = parse_flow_log_line(line)
            if parsed is not None:
                records.append(parsed)
            else:
                skipped += 1

        if not records:
            logger.warning("No valid records found in s3://%s/%s", bucket, key)
            return {"rows_inserted": 0, "rows_skipped": skipped, "aggregation_rows": 0}

        # 4. Bulk insert into log_events
        rows_inserted = await self._insert_log_events(
            records, customer_id, tenant_id, source_file=f"s3://{bucket}/{key}"
        )

        # 5. Compute and insert aggregations
        agg_rows = await self._insert_aggregations(records, customer_id, tenant_id)

        logger.info(
            "Completed VPC flow log processing: inserted=%d skipped=%d agg=%d",
            rows_inserted, skipped, agg_rows,
        )
        return {
            "rows_inserted": rows_inserted,
            "rows_skipped": skipped,
            "aggregation_rows": agg_rows,
        }

    def _download_from_s3(self, bucket: str, key: str) -> bytes:
        """Download an S3 object and return its raw bytes."""
        response = self._s3.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    async def _insert_log_events(
        self,
        records: List[Dict[str, Any]],
        customer_id: Optional[str],
        tenant_id: Optional[str],
        source_file: str = "",
    ) -> int:
        """Bulk insert parsed records into the log_events table.

        Returns:
            Number of rows inserted.
        """
        sql = """
            INSERT INTO log_events
                (source_type, customer_id, tenant_id, event_time,
                 src_ip, dst_ip, src_port, dst_port, protocol,
                 action, bytes_transferred, packets, interface_id,
                 log_status, source_file)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """
        rows: List[Tuple] = []
        for r in records:
            event_time = (
                datetime.fromtimestamp(r["start"], tz=timezone.utc)
                if r.get("start")
                else datetime.now(timezone.utc)
            )
            rows.append((
                "vpc_flow",
                customer_id,
                tenant_id,
                event_time,
                r.get("srcaddr"),            # INET — asyncpg handles string→inet
                r.get("dstaddr"),
                r.get("srcport"),
                r.get("dstport"),
                r.get("protocol_name"),
                r.get("action"),
                r.get("bytes", 0),
                r.get("packets", 0),
                r.get("interface_id"),
                r.get("log_status"),
                source_file,
            ))

        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

        return len(rows)

    async def _insert_aggregations(
        self,
        records: List[Dict[str, Any]],
        customer_id: Optional[str],
        tenant_id: Optional[str],
    ) -> int:
        """Compute 5-minute aggregations and insert into event_aggregations.

        Aggregation key: (src_ip, dst_ip, dst_port, protocol) per 5-min window.

        Returns:
            Number of aggregation rows inserted.
        """
        # Build aggregation buckets
        buckets: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
            "total_bytes": 0,
            "total_packets": 0,
            "flow_count": 0,
            "sources": set(),
            "destinations": set(),
            "accept_count": 0,
            "reject_count": 0,
        })

        for r in records:
            if not r.get("start"):
                continue

            window_start = _truncate_to_5min(r["start"])
            key = (
                r.get("srcaddr"),
                r.get("dstaddr"),
                r.get("dstport"),
                r.get("protocol_name"),
                window_start,
            )

            b = buckets[key]
            b["total_bytes"] += r.get("bytes", 0)
            b["total_packets"] += r.get("packets", 0)
            b["flow_count"] += 1
            if r.get("srcaddr"):
                b["sources"].add(r["srcaddr"])
            if r.get("dstaddr"):
                b["destinations"].add(r["dstaddr"])
            if r.get("action") == "ACCEPT":
                b["accept_count"] += 1
            elif r.get("action") == "REJECT":
                b["reject_count"] += 1

        if not buckets:
            return 0

        # Insert aggregation rows
        sql = """
            INSERT INTO event_aggregations
                (source_type, customer_id, tenant_id, window_start, window_end,
                 src_ip, dst_ip, dst_port, protocol,
                 total_bytes, total_packets, flow_count,
                 unique_sources, unique_destinations,
                 accept_count, reject_count)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        """
        rows: List[Tuple] = []
        for (src_ip, dst_ip, dst_port, protocol, window_start), b in buckets.items():
            from datetime import timedelta
            window_end = window_start + timedelta(minutes=5)
            rows.append((
                "vpc_flow",
                customer_id,
                tenant_id,
                window_start,
                window_end,
                src_ip,
                dst_ip,
                dst_port,
                protocol,
                b["total_bytes"],
                b["total_packets"],
                b["flow_count"],
                len(b["sources"]),
                len(b["destinations"]),
                b["accept_count"],
                b["reject_count"],
            ))

        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

        return len(rows)
