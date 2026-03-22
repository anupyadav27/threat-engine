"""
API Access Log Processor — Task 0.2.5 [Seq 17 | BD]

Queries API access logs from CloudWatch Logs (for API Gateway and ALB access logs),
parses the JSON/CLF format, aggregates by endpoint, and writes summaries to
log_events and event_aggregations.

Input:  CloudWatch log group names (from log_sources table)
Output: log_events (source_type='api_access'), event_aggregations (5-min summaries)

Dependencies:
  - Task 0.2.1 (log_collector_schema.sql)
  - Task 0.2.2 (log_source_registry)
  - Task 0.1.12 (CloudWatch log groups discovered)
"""

import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import boto3

logger = logging.getLogger("log_collector.processors.api_access")

# ---------------------------------------------------------------------------
# CLF (Common Log Format) parser for ALB access logs
# ---------------------------------------------------------------------------
ALB_LOG_PATTERN = re.compile(
    r'(?P<type>\S+) '
    r'(?P<timestamp>\S+) '
    r'(?P<elb>\S+) '
    r'(?P<client_ip>[\d.]+):(?P<client_port>\d+) '
    r'(?P<target_ip>[\d.-]+):?(?P<target_port>[\d-]+)? '
    r'(?P<request_processing_time>[\d.-]+) '
    r'(?P<target_processing_time>[\d.-]+) '
    r'(?P<response_processing_time>[\d.-]+) '
    r'(?P<elb_status_code>\d{3}) '
    r'(?P<target_status_code>[\d-]+) '
    r'(?P<received_bytes>\d+) '
    r'(?P<sent_bytes>\d+) '
    r'"(?P<request>[^"]*)" '
    r'"(?P<user_agent>[^"]*)" '
    r'(?P<ssl_cipher>\S+) '
    r'(?P<ssl_protocol>\S+)'
)


def _truncate_to_5min(dt: datetime) -> datetime:
    """Truncate a datetime to the nearest 5-minute boundary."""
    minute = (dt.minute // 5) * 5
    return dt.replace(minute=minute, second=0, microsecond=0)


def _is_error_status(status: int) -> bool:
    """Check if an HTTP status code indicates an error (4xx or 5xx)."""
    return status >= 400


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def parse_apigw_log(message: str) -> Optional[Dict[str, Any]]:
    """Parse an API Gateway CloudWatch JSON log entry.

    Expected JSON keys: requestId, ip, requestTime, httpMethod,
    resourcePath, status, protocol, responseLength, integrationLatency.
    """
    try:
        data = json.loads(message)
    except json.JSONDecodeError:
        return None

    status = data.get("status") or data.get("httpStatus")
    try:
        status = int(status) if status else 0
    except (ValueError, TypeError):
        status = 0

    latency_ms = None
    for key in ("integrationLatency", "latency", "responseLatency"):
        if key in data:
            try:
                latency_ms = float(data[key])
            except (ValueError, TypeError):
                pass
            break

    return {
        "source_ip": data.get("ip") or data.get("sourceIp"),
        "method": data.get("httpMethod", ""),
        "path": data.get("resourcePath") or data.get("path", ""),
        "status": status,
        "latency_ms": latency_ms,
        "bytes_sent": int(data.get("responseLength", 0) or 0),
        "protocol": data.get("protocol", ""),
    }


def parse_alb_log(message: str) -> Optional[Dict[str, Any]]:
    """Parse an ALB access log line (CLF-based format)."""
    match = ALB_LOG_PATTERN.match(message)
    if not match:
        return None

    groups = match.groupdict()

    # Parse request field: "METHOD path HTTP/version"
    request = groups.get("request", "")
    parts = request.split()
    method = parts[0] if len(parts) >= 1 else ""
    path = parts[1] if len(parts) >= 2 else ""

    # Compute total latency (ms)
    try:
        target_time = float(groups.get("target_processing_time", 0) or 0)
        latency_ms = target_time * 1000  # seconds → ms
    except (ValueError, TypeError):
        latency_ms = None

    try:
        status = int(groups.get("elb_status_code", 0))
    except (ValueError, TypeError):
        status = 0

    return {
        "source_ip": groups.get("client_ip"),
        "method": method,
        "path": path,
        "status": status,
        "latency_ms": latency_ms,
        "bytes_sent": int(groups.get("sent_bytes", 0) or 0),
        "protocol": groups.get("ssl_protocol", ""),
    }


# ---------------------------------------------------------------------------
# Processor
# ---------------------------------------------------------------------------
class APIAccessProcessor:
    """Queries and processes API access logs from CloudWatch Logs.

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
        region: str = "us-east-1",
        lookback_hours: int = 24,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process API access logs from a CloudWatch log group.

        Args:
            log_group_name: CloudWatch log group name.
            region: AWS region.
            lookback_hours: How far back to query (default 24h).
            customer_id: Customer identifier.
            tenant_id: Tenant identifier.

        Returns:
            Summary dict with rows_inserted, rows_skipped, aggregation_rows.
        """
        logger.info("Processing API access logs: log_group=%s lookback=%dh",
                     log_group_name, lookback_hours)

        # 1. Fetch log events from CloudWatch
        now = datetime.now(timezone.utc)
        start_time = int((now - timedelta(hours=lookback_hours)).timestamp() * 1000)

        events = self._fetch_log_events(log_group_name, start_time)

        if not events:
            logger.warning("No log events found in %s", log_group_name)
            return {"rows_inserted": 0, "rows_skipped": 0, "aggregation_rows": 0}

        # 2. Parse each event (try API GW JSON first, then ALB CLF)
        records: List[Dict[str, Any]] = []
        skipped = 0
        for event in events:
            message = event.get("message", "")
            timestamp_ms = event.get("timestamp", 0)
            event_time = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)

            parsed = parse_apigw_log(message) or parse_alb_log(message)
            if parsed:
                parsed["event_time"] = event_time
                records.append(parsed)
            else:
                skipped += 1

        # 3. Insert into log_events
        rows_inserted = await self._insert_log_events(
            records, customer_id, tenant_id, source_file=log_group_name
        )

        # 4. Compute and insert aggregations
        agg_rows = await self._insert_aggregations(records, customer_id, tenant_id)

        logger.info(
            "Completed API access log processing: inserted=%d skipped=%d agg=%d",
            rows_inserted, skipped, agg_rows,
        )
        return {
            "rows_inserted": rows_inserted,
            "rows_skipped": skipped,
            "aggregation_rows": agg_rows,
        }

    def _fetch_log_events(self, log_group_name: str, start_time_ms: int) -> List[Dict]:
        """Fetch log events from CloudWatch using filter_log_events.

        Handles pagination via nextToken.
        """
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
                logger.error("Failed to fetch logs from %s: %s", log_group_name, exc)
                break

            all_events.extend(response.get("events", []))

            next_token = response.get("nextToken")
            if not next_token:
                break
            params["nextToken"] = next_token

            # Safety limit to prevent runaway queries
            if len(all_events) >= 100000:
                logger.warning("Hit 100k event limit for %s, stopping pagination", log_group_name)
                break

        return all_events

    async def _insert_log_events(
        self,
        records: List[Dict[str, Any]],
        customer_id: Optional[str],
        tenant_id: Optional[str],
        source_file: str = "",
    ) -> int:
        """Insert parsed API access records into log_events."""
        sql = """
            INSERT INTO log_events
                (source_type, customer_id, tenant_id, event_time,
                 src_ip, dst_port, protocol, action,
                 bytes_transferred, source_file, raw_fields)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
        """
        rows: List[Tuple] = []
        for r in records:
            rows.append((
                "api_access",
                customer_id,
                tenant_id,
                r["event_time"],
                r.get("source_ip"),
                r.get("status"),              # store HTTP status in dst_port (numeric)
                r.get("protocol", ""),
                str(r.get("status", "")),      # action = status code as string
                r.get("bytes_sent", 0),
                source_file,
                json.dumps({
                    "method": r.get("method"),
                    "path": r.get("path"),
                    "latency_ms": r.get("latency_ms"),
                }),
            ))

        if rows:
            async with self._pool.acquire() as conn:
                await conn.executemany(sql, rows)

        return len(rows)

    async def _insert_aggregations(
        self,
        records: List[Dict[str, Any]],
        customer_id: Optional[str],
        tenant_id: Optional[str],
    ) -> int:
        """Compute 5-minute aggregations by (endpoint, method) and insert."""
        buckets: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
            "flow_count": 0,
            "error_count": 0,
            "total_bytes": 0,
            "sources": set(),
            "latencies": [],
        })

        for r in records:
            window_start = _truncate_to_5min(r["event_time"])
            key = (
                r.get("path", ""),
                r.get("method", ""),
                window_start,
            )
            b = buckets[key]
            b["flow_count"] += 1
            b["total_bytes"] += r.get("bytes_sent", 0)
            if r.get("source_ip"):
                b["sources"].add(r["source_ip"])
            if r.get("status") and _is_error_status(r["status"]):
                b["error_count"] += 1
            if r.get("latency_ms") is not None:
                b["latencies"].append(r["latency_ms"])

        if not buckets:
            return 0

        sql = """
            INSERT INTO event_aggregations
                (source_type, customer_id, tenant_id, window_start, window_end,
                 endpoint, http_method,
                 total_bytes, flow_count, unique_sources,
                 error_count, p99_latency_ms, avg_latency_ms)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        """
        rows: List[Tuple] = []
        for (endpoint, method, window_start), b in buckets.items():
            window_end = window_start + timedelta(minutes=5)

            # Compute p99 and avg latency
            latencies = sorted(b["latencies"])
            p99 = None
            avg = None
            if latencies:
                idx = max(0, int(len(latencies) * 0.99) - 1)
                p99 = latencies[idx]
                avg = sum(latencies) / len(latencies)

            rows.append((
                "api_access",
                customer_id,
                tenant_id,
                window_start,
                window_end,
                endpoint,
                method,
                b["total_bytes"],
                b["flow_count"],
                len(b["sources"]),
                b["error_count"],
                p99,
                avg,
            ))

        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)

        return len(rows)
