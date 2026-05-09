"""
IBM Cloud Object Storage Reader — S3-compatible API.

Uses ibm-cos-sdk which wraps boto3 with IBM COS endpoints.
"""

import gzip
import logging
from datetime import datetime
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class IBMCOSReader(BaseReader):
    """Read log files from IBM Cloud Object Storage (S3-compatible)."""

    storage_type = "ibm_cos"

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        try:
            import ibm_boto3
            from ibm_botocore.client import Config

            if hasattr(session, "list_objects_v2"):
                cos = session
            else:
                cos = ibm_boto3.client(
                    "s3",
                    ibm_api_key_id=session.get("api_key", ""),
                    ibm_service_instance_id=session.get("service_instance_id", ""),
                    config=Config(signature_version="oauth"),
                    endpoint_url=session.get("endpoint", "https://s3.us-south.cloud-object-storage.appdomain.cloud"),
                )

            bucket = source.location
            prefix = source.prefix or ""
            total_bytes = 0

            paginator = cos.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    last_mod = obj.get("LastModified")
                    if last_mod and last_mod < start_time:
                        continue

                    resp = cos.get_object(Bucket=bucket, Key=key)
                    raw = resp["Body"].read()
                    total_bytes += len(raw)

                    try:
                        raw = gzip.decompress(raw)
                    except (gzip.BadGzipFile, OSError):
                        pass

                    yield raw

                    if total_bytes >= max_bytes:
                        return

            logger.info(f"IBM COS reader: {total_bytes / 1024:.1f} KB from {bucket}")

        except ImportError:
            logger.warning("ibm-cos-sdk not installed")
        except Exception as exc:
            logger.error(f"IBM COS reader error: {exc}")

    def list_log_files(self, session, source, start_time, end_time):
        return []
