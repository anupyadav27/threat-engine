"""CloudTrail JSON parser — {"Records": [{event}, ...]}"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class CloudTrailParser(BaseParser):
    format_name = "cloudtrail"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            data = json.loads(raw_bytes)
            for record in data.get("Records", []):
                # Normalize eventSource: s3.amazonaws.com → s3
                es = record.get("eventSource", "")
                if es.endswith(".amazonaws.com"):
                    record["_service"] = es.replace(".amazonaws.com", "")
                else:
                    record["_service"] = es
                yield record
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.debug(f"CloudTrail parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_id": "eventID",
            "service": "_service",
            "operation": "eventName",
            "actor.ip_address": "sourceIPAddress",
            "actor.user_agent": "userAgent",
            "resource.region": "awsRegion",
            "resource.account_id": "recipientAccountId",
        }

    def get_event_category(self) -> str:
        return EventCategory.API_ACTIVITY
