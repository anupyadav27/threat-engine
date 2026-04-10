"""
AWS CloudWatch Logs Reader — reads log events from CloudWatch log groups.

Used for: EKS Audit, RDS Audit, Route53 DNS, Lambda logs.
CloudWatch stores logs as streams within log groups.
"""

import gzip
import json
import logging
from datetime import datetime
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class AWSCloudWatchReader(BaseReader):
    """Read log events from AWS CloudWatch Logs."""

    storage_type = "cloudwatch"

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        """Yield log event batches as JSON bytes from CloudWatch.

        Each yield is a JSON-encoded list of log events (one batch).
        """
        client = session.client("logs", region_name=source.region or "ap-south-1")
        log_group = source.location
        stream_prefix = source.prefix or ""

        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        total_bytes = 0
        total_events = 0

        try:
            # Find matching log streams
            streams = self._list_streams(client, log_group, stream_prefix, start_ms, end_ms)
            if not streams:
                logger.info(f"CloudWatch: no streams in {log_group} (prefix={stream_prefix})")
                return

            logger.info(f"CloudWatch: {len(streams)} streams in {log_group}")

            # Read events from each stream
            for stream_name in streams:
                kwargs = {
                    "logGroupName": log_group,
                    "logStreamName": stream_name,
                    "startTime": start_ms,
                    "endTime": end_ms,
                    "startFromHead": True,
                }

                while True:
                    try:
                        resp = client.get_log_events(**kwargs)
                    except client.exceptions.ResourceNotFoundException:
                        break
                    except Exception as exc:
                        logger.debug(f"CloudWatch get_log_events failed: {exc}")
                        break

                    events = resp.get("events", [])
                    if not events:
                        break

                    # Yield batch as JSON bytes
                    batch = []
                    for evt in events:
                        msg = evt.get("message", "")
                        batch.append({
                            "message": msg,
                            "timestamp": evt.get("timestamp", 0),
                            "ingestionTime": evt.get("ingestionTime", 0),
                            "logStreamName": stream_name,
                        })
                        total_events += 1

                    data = json.dumps(batch).encode("utf-8")
                    total_bytes += len(data)
                    yield data

                    if total_bytes >= max_bytes:
                        logger.info(f"CloudWatch: hit max_bytes ({max_bytes})")
                        return

                    # Pagination
                    next_token = resp.get("nextForwardToken")
                    if next_token == kwargs.get("nextToken"):
                        break  # No more events
                    kwargs["nextToken"] = next_token

            logger.info(
                f"CloudWatch reader: {total_events} events from {log_group} "
                f"({total_bytes / 1024:.1f} KB)"
            )

        except Exception as exc:
            logger.error(f"CloudWatch reader error for {log_group}: {exc}")

    def _list_streams(
        self, client, log_group: str, prefix: str,
        start_ms: int, end_ms: int,
    ) -> List[str]:
        """List log streams with recent activity."""
        streams = []
        try:
            kwargs = {
                "logGroupName": log_group,
                "orderBy": "LastEventTime",
                "descending": True,
                "limit": 50,  # Top 50 most recent streams
            }
            if prefix:
                kwargs["logStreamNamePrefix"] = prefix

            resp = client.describe_log_streams(**kwargs)
            for s in resp.get("logStreams", []):
                last_event = s.get("lastEventTimestamp", 0)
                # Only include streams with events in our time range
                if last_event >= start_ms:
                    streams.append(s["logStreamName"])
        except client.exceptions.ResourceNotFoundException:
            logger.debug(f"Log group not found: {log_group}")
        except Exception as exc:
            logger.debug(f"Failed to list streams for {log_group}: {exc}")

        return streams

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List available log streams."""
        client = session.client("logs", region_name=source.region or "ap-south-1")
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)

        streams = self._list_streams(client, source.location, source.prefix, start_ms, end_ms)
        return [{"key": s, "size": 0, "last_modified": None} for s in streams]
