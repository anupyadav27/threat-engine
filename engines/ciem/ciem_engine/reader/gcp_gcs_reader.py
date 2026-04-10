"""
GCP Cloud Storage (GCS) Log Reader.

Reads log files exported to GCS via Cloud Logging sinks.
Works for: GCP Audit Logs, VPC Flow Logs, any log type routed to GCS.

Uses the google-cloud-storage SDK. The caller provides an authenticated
google.cloud.storage.Client (or credentials) as the session parameter.

GCS sink typical prefix structure:
  gs://<bucket>/<sink-name>/<YYYY>/<MM>/<DD>/...
"""

import gzip
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class GCPGCSReader(BaseReader):
    """Read log files stored in Google Cloud Storage."""

    storage_type = "gcs"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List GCS blobs matching the time range.

        Args:
            session: google.cloud.storage.Client instance
            source: LogSource with location=bucket name, prefix=blob prefix
            start_time: Only include blobs modified after this time
            end_time: Only include blobs modified before this time

        Returns:
            List of dicts with: key, size, last_modified
        """
        client = self._get_client(session)
        bucket = client.bucket(source.location)
        files: List[Dict[str, Any]] = []

        prefixes = self._build_date_prefixes(source, start_time, end_time)

        for prefix in prefixes:
            try:
                blobs = client.list_blobs(bucket, prefix=prefix)
                for blob in blobs:
                    # Filter by time range
                    modified = blob.updated or blob.time_created
                    if modified:
                        if modified.tzinfo is None:
                            modified = modified.replace(tzinfo=timezone.utc)
                        if modified < start_time:
                            continue
                        if modified > end_time:
                            continue

                    files.append({
                        "key": blob.name,
                        "size": blob.size or 0,
                        "last_modified": modified,
                    })
            except Exception as exc:
                logger.warning(
                    f"Failed to list gs://{source.location}/{prefix}: {exc}"
                )

        logger.info(
            f"GCS reader: found {len(files)} files in "
            f"gs://{source.location}/{source.prefix} "
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
        """Yield decompressed content of each log file from GCS.

        Args:
            session: google.cloud.storage.Client instance
            source: LogSource describing the GCS bucket and prefix
            start_time: Start of time window
            end_time: End of time window
            max_bytes: Stop after reading this many raw bytes
        """
        client = self._get_client(session)
        bucket = client.bucket(source.location)
        files = self.list_log_files(session, source, start_time, end_time)

        total_bytes = 0
        for file_info in files:
            if total_bytes >= max_bytes:
                logger.warning(f"GCS reader: hit max_bytes limit ({max_bytes})")
                return

            key = file_info["key"]
            try:
                blob = bucket.blob(key)
                body = blob.download_as_bytes()
                total_bytes += len(body)

                # Decompress if gzipped
                if key.endswith(".gz"):
                    body = gzip.decompress(body)

                yield body

            except Exception as exc:
                logger.debug(f"Failed to read gs://{source.location}/{key}: {exc}")
                continue

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_client(session: Any) -> Any:
        """Accept either a storage.Client directly or create one from credentials.

        Args:
            session: google.cloud.storage.Client or google.auth.credentials.Credentials

        Returns:
            google.cloud.storage.Client
        """
        # If it's already a Client, use it directly
        try:
            from google.cloud.storage import Client as StorageClient
            if isinstance(session, StorageClient):
                return session
        except ImportError:
            pass

        # If it's credentials, wrap in a Client
        try:
            from google.cloud import storage as gcs_module
            return gcs_module.Client(credentials=session)
        except Exception:
            # Last resort: assume it's a Client-like object
            return session

    @staticmethod
    def _build_date_prefixes(
        source: LogSource, start_time: datetime, end_time: datetime
    ) -> List[str]:
        """Build GCS prefixes for each day in the time range.

        GCS log sink typical structure:
            <prefix>/<YYYY>/<MM>/<DD>/
        """
        base = source.prefix or ""
        if base and not base.endswith("/"):
            base += "/"

        prefixes = []
        current = start_time
        while current.date() <= end_time.date():
            prefixes.append(
                f"{base}{current.year:04d}/{current.month:02d}/{current.day:02d}/"
            )
            current += timedelta(days=1)

        return prefixes
