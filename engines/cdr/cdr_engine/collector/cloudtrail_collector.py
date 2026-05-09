"""
CloudTrail Log Collector

Reads CloudTrail logs from S3 (not via API — reads the actual log files
stored by CloudTrail in the trail's S3 bucket).

CloudTrail S3 structure:
  s3://{bucket}/AWSLogs/{account}/CloudTrail/{region}/{year}/{month}/{day}/{file}.json.gz

Each file contains: {"Records": [{event1}, {event2}, ...]}
"""

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from .base_collector import BaseCollector
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class CloudTrailCollector(BaseCollector):
    source_type = "cloudtrail"
    category = EventCategory.API_ACTIVITY

    def __init__(self, trail_bucket: str = "", trail_prefix: str = "", **kwargs):
        super().__init__(**kwargs)
        self.trail_bucket = trail_bucket
        self.trail_prefix = trail_prefix

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_id": "eventID",
            "service": "eventSource",            # s3.amazonaws.com → s3
            "operation": "eventName",             # GetObject, PutObject
            "actor.ip_address": "sourceIPAddress",
            "actor.user_agent": "userAgent",
            "resource.region": "awsRegion",
        }

    def find_log_sources(self, boto_session) -> List[Dict[str, str]]:
        """Find CloudTrail log S3 prefixes for the lookback window."""
        if not self.trail_bucket:
            # Try to discover trail bucket from inventory or direct API
            self.trail_bucket, self.trail_prefix = self._discover_trail(boto_session)
            if not self.trail_bucket:
                logger.warning("No CloudTrail S3 bucket found")
                return []

        sources = []
        # Build S3 prefixes for each day in the lookback window
        current = self.start_time
        while current <= self.end_time:
            prefix = (
                f"{self.trail_prefix}AWSLogs/{self.account_id}/CloudTrail/"
                f"{self.region}/{current.year:04d}/{current.month:02d}/{current.day:02d}/"
            )
            sources.append({
                "bucket": self.trail_bucket,
                "prefix": prefix,
                "region": self.region,
            })
            current += __import__("datetime").timedelta(days=1)

        return sources

    def read_and_parse(self, boto_session, source: Dict) -> Generator[Dict, None, None]:
        """Read CloudTrail JSON.gz files from S3 and yield event dicts."""
        bucket = source["bucket"]
        prefix = source["prefix"]

        try:
            s3 = boto_session.client("s3", region_name=source.get("region", self.region))
        except Exception as exc:
            logger.warning(f"Failed to create S3 client: {exc}")
            return

        # List objects with prefix
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith(".json.gz"):
                        continue

                    try:
                        response = s3.get_object(Bucket=bucket, Key=key)
                        body = response["Body"].read()
                        data = json.loads(gzip.decompress(body))
                        records = data.get("Records", [])

                        for record in records:
                            # Post-process: normalize eventSource
                            es = record.get("eventSource", "")
                            if es.endswith(".amazonaws.com"):
                                record["eventSource"] = es.replace(".amazonaws.com", "")

                            # Filter by time
                            event_time = record.get("eventTime", "")
                            if event_time:
                                try:
                                    et = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                                    if et < self.start_time:
                                        continue
                                except (ValueError, TypeError):
                                    pass

                            yield record

                    except Exception as file_exc:
                        logger.debug(f"Failed to read {key}: {file_exc}")
                        continue

        except Exception as exc:
            logger.warning(f"Failed to list CloudTrail logs at s3://{bucket}/{prefix}: {exc}")

    def _discover_trail(self, boto_session) -> tuple:
        """Discover CloudTrail bucket from the AWS API."""
        try:
            ct = boto_session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails().get("trailList", [])
            for trail in trails:
                bucket = trail.get("S3BucketName")
                prefix = trail.get("S3KeyPrefix", "")
                if bucket:
                    if prefix and not prefix.endswith("/"):
                        prefix += "/"
                    logger.info(f"Discovered CloudTrail: s3://{bucket}/{prefix}")
                    return bucket, prefix
        except Exception as exc:
            logger.warning(f"Failed to discover CloudTrail: {exc}")
        return "", ""
