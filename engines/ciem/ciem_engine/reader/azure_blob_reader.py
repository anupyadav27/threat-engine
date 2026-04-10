"""
Azure Blob Storage reader — reads ANY log type stored in Azure Blob containers.

Works for: Activity Logs, NSG Flow Logs, Application Gateway logs,
Azure AD sign-in logs, Defender alerts.

The reader doesn't parse — it yields raw file content (bytes).
The parser handles format-specific parsing.

Requires: azure-storage-blob SDK
  pip install azure-storage-blob

Credential flow:
  The orchestrator passes an Azure credential object (e.g.
  DefaultAzureCredential, ClientSecretCredential) via the session parameter.
  This reader uses it to construct a BlobServiceClient.
"""

import gzip
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class AzureBlobReader(BaseReader):
    """Reads log files from Azure Blob Storage containers."""

    storage_type = "azure_storage"

    def _get_container_client(self, session: Any, source: LogSource) -> Any:
        """Build a ContainerClient from the session credential.

        Args:
            session: Azure credential object (DefaultAzureCredential, etc.).
            source: LogSource with location set to storage account name
                    and metadata['container'] set to container name.

        Returns:
            azure.storage.blob.ContainerClient instance.
        """
        from azure.storage.blob import BlobServiceClient

        storage_account = source.location
        container_name = source.metadata.get("container", "insights-logs-default")
        account_url = f"https://{storage_account}.blob.core.windows.net"

        blob_service = BlobServiceClient(account_url=account_url, credential=session)
        return blob_service.get_container_client(container_name)

    def _build_prefix(self, source: LogSource, day: datetime) -> str:
        """Build blob prefix for a specific day.

        Azure diagnostic logs use this structure:
          resourceId=<ARM-resource-id>/y=YYYY/m=MM/d=DD/h=HH/m=00/

        Args:
            source: LogSource with prefix and metadata.
            day: Date to build prefix for.

        Returns:
            Blob name prefix string.
        """
        base = source.prefix or ""

        if source.source_type == "azure_activity":
            # Activity logs: insights-activity-logs/resourceId=.../y=YYYY/m=MM/d=DD/
            return (
                f"{base}"
                f"y={day.year:04d}/m={day.month:02d}/d={day.day:02d}/"
            )
        elif source.source_type == "azure_nsg_flow":
            # NSG flow logs: insights-logs-networksecuritygroupflowevent/resourceId=.../y=YYYY/m=MM/d=DD/
            return (
                f"{base}"
                f"y={day.year:04d}/m={day.month:02d}/d={day.day:02d}/"
            )
        else:
            return f"{base}{day.year:04d}/{day.month:02d}/{day.day:02d}/"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List blobs matching the time range.

        Args:
            session: Azure credential object.
            source: LogSource describing the storage account and container.
            start_time: Only include blobs from this time onward.
            end_time: Only include blobs up to this time.

        Returns:
            List of dicts with keys: key, size, last_modified.
        """
        container_client = self._get_container_client(session, source)
        files: List[Dict[str, Any]] = []

        # Build day-based prefixes
        current = start_time
        while current.date() <= end_time.date():
            prefix = self._build_prefix(source, current)
            try:
                blobs = container_client.list_blobs(name_starts_with=prefix)
                for blob in blobs:
                    last_modified = blob.last_modified
                    if last_modified and last_modified < start_time:
                        continue
                    files.append({
                        "key": blob.name,
                        "size": blob.size or 0,
                        "last_modified": last_modified,
                    })
            except Exception as exc:
                logger.warning(
                    "Failed to list blobs in %s/%s: %s",
                    source.location, prefix, exc,
                )
            current += timedelta(days=1)

        logger.info(
            "Azure Blob reader: found %d files in %s/%s (%s) (%.1f MB)",
            len(files),
            source.location,
            source.metadata.get("container", ""),
            source.prefix,
            sum(f["size"] for f in files) / 1024 / 1024,
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
        """Yield decompressed content of each log blob.

        Args:
            session: Azure credential object.
            source: LogSource describing the storage account and container.
            start_time: Only read events after this time.
            end_time: Only read events before this time.
            max_bytes: Stop after reading this many bytes.

        Yields:
            Decompressed bytes for each blob file.
        """
        container_client = self._get_container_client(session, source)
        files = self.list_log_files(session, source, start_time, end_time)

        total_bytes = 0
        for file_info in files:
            if total_bytes >= max_bytes:
                logger.warning(
                    "Azure Blob reader: hit max_bytes limit (%d)", max_bytes
                )
                return

            blob_name = file_info["key"]
            try:
                blob_client = container_client.get_blob_client(blob_name)
                body = blob_client.download_blob().readall()
                total_bytes += len(body)

                # Decompress if gzipped
                if blob_name.endswith(".gz"):
                    body = gzip.decompress(body)
                elif blob_name.endswith(".json.gz"):
                    body = gzip.decompress(body)

                yield body

            except Exception as exc:
                logger.debug(
                    "Failed to read blob %s/%s: %s",
                    source.location, blob_name, exc,
                )
                continue
