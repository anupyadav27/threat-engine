"""
Base Log Reader — reads raw bytes/lines from a cloud storage location.

Readers know HOW to get data, not WHAT the data means.
One reader per cloud storage type:
  - AWS S3 (CloudTrail, VPC Flow, ALB, WAF, S3 Access logs)
  - AWS CloudWatch Logs (DNS, Lambda, RDS audit)
  - Azure Storage Account (Activity, NSG Flow, App GW)
  - Azure Log Analytics (queries via API)
  - GCP Cloud Logging (all GCP logs via single API)

For multi-account SaaS:
  Reader receives a boto session with assumed-role credentials.
  It doesn't manage credentials — the orchestrator does.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


class LogSource:
    """Describes where a specific log lives."""
    def __init__(
        self,
        source_type: str,        # cloudtrail, vpc_flow, s3_access, alb, waf, dns
        storage_type: str,       # s3, cloudwatch, azure_storage, gcp_logging
        location: str,           # bucket name, log group, storage account
        prefix: str = "",        # S3 prefix, log stream
        region: str = "",
        account_id: str = "",
        format: str = "json_gz", # json_gz, json, csv, parquet, text
        metadata: Dict = None,
    ):
        self.source_type = source_type
        self.storage_type = storage_type
        self.location = location
        self.prefix = prefix
        self.region = region
        self.account_id = account_id
        self.format = format
        self.metadata = metadata or {}


class BaseReader(ABC):
    """Abstract base for cloud storage readers."""

    storage_type: str = ""  # Override: "s3", "cloudwatch", "azure_storage", "gcp_logging"

    @abstractmethod
    def read(
        self,
        session: Any,           # boto3 session, azure credential, gcp credential
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,  # 500MB limit per source
    ) -> Generator[bytes, None, None]:
        """Yield raw bytes/chunks from the log source.

        Args:
            session: Cloud SDK session with appropriate credentials
            source: LogSource describing where to read
            start_time: Only read events after this time
            end_time: Only read events before this time
            max_bytes: Stop after reading this many bytes
        """
        ...

    @abstractmethod
    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """List available log files/streams for the time range.

        Returns list of dicts with: key, size, last_modified
        """
        ...
