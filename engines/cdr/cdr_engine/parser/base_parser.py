"""
Base Log Parser — converts raw bytes into structured event dicts.

Parsers know WHAT the data format is, not WHERE it came from.
One parser per log format:
  - CloudTrail JSON (Records array)
  - VPC Flow Logs (space-delimited CSV)
  - S3 Access Logs (space-delimited, quoted strings)
  - ALB Access Logs (space-delimited)
  - WAF JSON (single event per line)
  - Azure Activity JSON
  - GCP Audit JSON
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, List

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Abstract base for log format parsers."""

    format_name: str = ""  # Override: "cloudtrail", "vpc_flow", etc.

    @abstractmethod
    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse raw bytes and yield individual event dicts.

        Args:
            raw_bytes: Decompressed file content

        Yields:
            Dict representing one event in the source's native format
        """
        ...

    @abstractmethod
    def get_field_mapping(self) -> Dict[str, str]:
        """Return mapping: source field path → NormalizedEvent field path.

        Example: {"eventName": "operation", "sourceIPAddress": "actor.ip_address"}
        """
        ...

    @abstractmethod
    def get_event_category(self) -> str:
        """Return the EventCategory for this log type."""
        ...
