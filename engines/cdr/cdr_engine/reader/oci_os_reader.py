"""
OCI Object Storage Log Reader — reads log files from OCI Object Storage buckets.

Uses the `oci` Python SDK. OCI stores audit logs and VCN flow logs in
Object Storage buckets with date-partitioned prefixes.

For multi-tenancy: receives an oci.config dict or signer with the
appropriate credentials. The orchestrator manages credential lifecycle.
"""

import gzip
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class OCIObjectStorageReader(BaseReader):
    """Reader for logs stored in OCI Object Storage buckets."""

    storage_type = "oci_os"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List OCI Object Storage objects matching the time range.

        Args:
            session: Dict with 'config' (oci config dict) and optional 'signer'.
                     Example: {"config": oci_config} or {"config": {}, "signer": instance_principal_signer}
            source: LogSource with location=<namespace/bucket>, prefix, region
            start_time: Only include objects modified after this time
            end_time: Only include objects modified before this time

        Returns:
            List of dicts with key, size, last_modified
        """
        try:
            import oci
        except ImportError:
            logger.error("oci SDK not installed — run: pip install oci")
            return []

        config = session.get("config", {})
        signer = session.get("signer", None)

        # Parse namespace and bucket from location: "namespace/bucket"
        namespace, bucket = self._parse_location(source.location)
        if not namespace or not bucket:
            logger.error(f"Invalid OCI OS location: {source.location} (expected 'namespace/bucket')")
            return []

        kwargs = {"config": config}
        if signer:
            kwargs["signer"] = signer

        os_client = oci.object_storage.ObjectStorageClient(**kwargs)

        files: List[Dict[str, Any]] = []
        prefixes = self._build_date_prefixes(source, start_time, end_time)

        for prefix in prefixes:
            try:
                next_start = None
                while True:
                    response = os_client.list_objects(
                        namespace_name=namespace,
                        bucket_name=bucket,
                        prefix=prefix,
                        start=next_start,
                        limit=1000,
                    )
                    for obj in response.data.objects:
                        # Filter by time if available
                        modified = obj.time_modified
                        if modified:
                            if modified.replace(tzinfo=timezone.utc) < start_time:
                                continue
                            if modified.replace(tzinfo=timezone.utc) > end_time:
                                continue
                        files.append({
                            "key": obj.name,
                            "size": obj.size or 0,
                            "last_modified": modified,
                        })

                    next_start = response.data.next_start_with
                    if not next_start:
                        break

            except Exception as exc:
                logger.warning(f"Failed to list oci://{namespace}/{bucket}/{prefix}: {exc}")

        logger.info(
            f"OCI OS reader: found {len(files)} files in "
            f"oci://{namespace}/{bucket}/{source.prefix} "
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
        """Yield decompressed content of each log file from OCI Object Storage.

        Args:
            session: Dict with 'config' and optional 'signer'
            source: LogSource describing the OCI OS location
            start_time: Read events after this time
            end_time: Read events before this time
            max_bytes: Stop after reading this many bytes

        Yields:
            Decompressed bytes for each log file
        """
        try:
            import oci
        except ImportError:
            logger.error("oci SDK not installed — run: pip install oci")
            return

        config = session.get("config", {})
        signer = session.get("signer", None)

        namespace, bucket = self._parse_location(source.location)
        if not namespace or not bucket:
            return

        kwargs = {"config": config}
        if signer:
            kwargs["signer"] = signer

        os_client = oci.object_storage.ObjectStorageClient(**kwargs)
        files = self.list_log_files(session, source, start_time, end_time)

        total_bytes = 0
        for file_info in files:
            if total_bytes >= max_bytes:
                logger.warning(f"OCI OS reader: hit max_bytes limit ({max_bytes})")
                return

            key = file_info["key"]
            try:
                response = os_client.get_object(
                    namespace_name=namespace,
                    bucket_name=bucket,
                    object_name=key,
                )
                body = response.data.content
                total_bytes += len(body)

                # Decompress if gzipped
                if key.endswith(".gz"):
                    body = gzip.decompress(body)

                yield body

            except Exception as exc:
                logger.debug(f"Failed to read oci://{namespace}/{bucket}/{key}: {exc}")
                continue

    def _parse_location(self, location: str) -> tuple:
        """Parse 'namespace/bucket' from location string.

        Args:
            location: String in format 'namespace/bucket'

        Returns:
            Tuple of (namespace, bucket) or ("", "") on failure
        """
        parts = location.split("/", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return "", ""

    def _build_date_prefixes(
        self, source: LogSource, start_time: datetime, end_time: datetime
    ) -> List[str]:
        """Build date-partitioned prefixes for the time range.

        OCI audit logs typically use: <prefix>/YYYY/MM/DD/ structure.

        Args:
            source: LogSource with prefix info
            start_time: Start of time window
            end_time: End of time window

        Returns:
            List of prefix strings to search
        """
        base = source.prefix or ""
        if base and not base.endswith("/"):
            base += "/"

        if source.source_type == "oci_audit":
            # OCI Audit logs: <prefix>/<tenancy_ocid>/YYYY/MM/DD/
            pattern = f"{base}{{year}}/{{month}}/{{day}}/"
        elif source.source_type == "oci_vcn_flow":
            # VCN Flow logs: <prefix>/<vcn_ocid>/YYYY/MM/DD/
            pattern = f"{base}{{year}}/{{month}}/{{day}}/"
        else:
            pattern = f"{base}{{year}}/{{month}}/{{day}}/"

        prefixes: List[str] = []
        current = start_time
        while current.date() <= end_time.date():
            prefixes.append(pattern.format(
                year=f"{current.year:04d}",
                month=f"{current.month:02d}",
                day=f"{current.day:02d}",
            ))
            current += timedelta(days=1)

        return prefixes
