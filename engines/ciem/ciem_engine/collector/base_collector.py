"""
Base Log Collector — ABC for all log source collectors.

Each collector knows how to:
1. Find log files (S3 prefix, CloudWatch log group)
2. Read log files (S3 GetObject, CloudWatch GetLogEvents)
3. Parse the raw format into dicts
4. Hand off to EventNormalizer for schema mapping
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional

from ..normalizer.schema import NormalizedEvent
from ..normalizer.event_normalizer import EventNormalizer

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base for log collectors."""

    source_type: str = ""  # Override in subclass
    category: str = ""     # EventCategory value

    def __init__(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        region: str,
        lookback_hours: int = 24,
        max_events: int = 100_000,
        asset_index: Optional[Dict[str, Dict]] = None,
    ):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.region = region
        self.lookback_hours = lookback_hours
        self.max_events = max_events
        self.asset_index = asset_index or {}

        self.start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        self.end_time = datetime.now(timezone.utc)

    @abstractmethod
    def get_field_mapping(self) -> Dict[str, str]:
        """Return source field → NormalizedEvent field mapping."""
        ...

    @abstractmethod
    def find_log_sources(self, boto_session) -> List[Dict[str, str]]:
        """Find log file locations (S3 keys, CW log groups).

        Returns list of dicts with at least: {"bucket": "...", "prefix": "..."}
        or {"log_group": "...", "stream": "..."}.
        """
        ...

    @abstractmethod
    def read_and_parse(self, boto_session, source: Dict) -> Generator[Dict, None, None]:
        """Read log files from source and yield parsed raw event dicts."""
        ...

    def collect(self, boto_session) -> List[NormalizedEvent]:
        """Main collection flow: find → read → normalize."""
        normalizer = EventNormalizer(
            source_type=self.source_type,
            field_mapping=self.get_field_mapping(),
            category=self.category,
            scan_run_id=self.scan_run_id,
            tenant_id=self.tenant_id,
            asset_index=self.asset_index,
        )

        all_events: List[NormalizedEvent] = []
        sources = self.find_log_sources(boto_session)
        logger.info(
            f"[{self.source_type}] Found {len(sources)} log sources "
            f"(lookback={self.lookback_hours}h, max={self.max_events})"
        )

        for source in sources:
            source_key = source.get("prefix", source.get("log_group", ""))
            normalizer.source_bucket = source.get("bucket", "")
            normalizer.source_region = source.get("region", self.region)

            event_count = 0
            for raw_event in self.read_and_parse(boto_session, source):
                event = normalizer.normalize(raw_event, source_key)
                if event:
                    all_events.append(event)
                    event_count += 1
                    if len(all_events) >= self.max_events:
                        logger.warning(
                            f"[{self.source_type}] Hit max_events limit ({self.max_events})"
                        )
                        return all_events

            logger.info(f"[{self.source_type}] {source_key}: {event_count} events")

        logger.info(f"[{self.source_type}] Total: {len(all_events)} events from {len(sources)} sources")
        return all_events
