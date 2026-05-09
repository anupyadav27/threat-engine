"""
AWS S3 Log Reader — reads ANY log type stored in S3.

Works for: CloudTrail, VPC Flow Logs, ALB Access Logs, WAF Logs,
S3 Access Logs, CloudFront Logs.

The reader doesn't parse — it yields raw file content (bytes).
The parser handles format-specific parsing.
"""

import gzip
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class AWSS3Reader(BaseReader):
    storage_type = "s3"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List S3 objects matching the time range."""
        s3 = session.client("s3", region_name=source.region or "us-east-1")
        files = []

        # Build date-based prefixes (most log types use YYYY/MM/DD structure)
        prefixes = self._build_date_prefixes(source, start_time, end_time)

        for prefix in prefixes:
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=source.location, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        # Filter by last modified time
                        modified = obj.get("LastModified")
                        if modified and modified.replace(tzinfo=timezone.utc) < start_time:
                            continue
                        files.append({
                            "key": obj["Key"],
                            "size": obj.get("Size", 0),
                            "last_modified": modified,
                        })
            except Exception as exc:
                logger.warning(f"Failed to list s3://{source.location}/{prefix}: {exc}")

        logger.info(
            f"S3 reader: found {len(files)} files in "
            f"s3://{source.location}/{source.prefix} "
            f"({sum(f['size'] for f in files) / 1024 / 1024:.1f} MB)"
        )
        return files

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        """Yield decompressed content of each log file."""
        s3 = session.client("s3", region_name=source.region or "us-east-1")
        files = self.list_log_files(session, source, start_time, end_time)

        total_bytes = 0
        for file_info in files:
            if total_bytes >= max_bytes:
                logger.warning(f"S3 reader: hit max_bytes limit ({max_bytes})")
                return

            key = file_info["key"]
            try:
                response = s3.get_object(Bucket=source.location, Key=key)
                body = response["Body"].read()
                total_bytes += len(body)

                # Decompress if gzipped
                if key.endswith(".gz"):
                    body = gzip.decompress(body)

                yield body

            except Exception as exc:
                logger.debug(f"Failed to read s3://{source.location}/{key}: {exc}")
                continue

    def _build_date_prefixes(
        self, source: LogSource, start_time: datetime, end_time: datetime
    ) -> List[str]:
        """Build S3 prefixes for each day in the time range."""
        base = source.prefix or ""
        account = source.account_id

        # Different log types have different S3 prefix patterns
        if source.source_type == "cloudtrail":
            # AWSLogs/{account}/CloudTrail/{region}/YYYY/MM/DD/
            region = source.region or "us-east-1"
            pattern = f"{base}AWSLogs/{account}/CloudTrail/{region}/{{year}}/{{month}}/{{day}}/"
        elif source.source_type == "vpc_flow":
            # AWSLogs/{account}/vpcflowlogs/{region}/YYYY/MM/DD/
            region = source.region or "us-east-1"
            pattern = f"{base}AWSLogs/{account}/vpcflowlogs/{region}/{{year}}/{{month}}/{{day}}/"
        elif source.source_type == "alb":
            # AWSLogs/{account}/elasticloadbalancing/{region}/YYYY/MM/DD/
            region = source.region or "us-east-1"
            pattern = f"{base}AWSLogs/{account}/elasticloadbalancing/{region}/{{year}}/{{month}}/{{day}}/"
        else:
            # Generic: just use base prefix + date
            pattern = f"{base}{{year}}/{{month}}/{{day}}/"

        prefixes = []
        current = start_time
        while current.date() <= end_time.date():
            prefixes.append(pattern.format(
                year=f"{current.year:04d}",
                month=f"{current.month:02d}",
                day=f"{current.day:02d}",
            ))
            current += timedelta(days=1)

        return prefixes
