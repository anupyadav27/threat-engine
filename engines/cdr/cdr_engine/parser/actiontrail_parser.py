"""
AliCloud ActionTrail log parser.

ActionTrail is AliCloud's audit log service (equivalent to AWS CloudTrail).
Events are fetched via the ActionTrail LookupEvents API and returned as JSON.

Event format:
{
  "eventId": "...",
  "eventName": "DeleteRole",
  "serviceName": "Ram",
  "eventTime": "2024-01-01T00:00:00Z",
  "userIdentity": {
    "type": "ram-user",
    "principalId": "...",
    "accountId": "5181776522508288",
    "userName": "admin"
  },
  "sourceIpAddress": "1.2.3.4",
  "requestParameters": {...},
  "responseElements": {...},
  "errorCode": null,
  "errorMessage": null,
  "region": "cn-hangzhou"
}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class ActionTrailParser(BaseParser):
    """Parser for AliCloud ActionTrail JSON events."""

    format_name = "alicloud_actiontrail"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse a batch of ActionTrail events (JSON array).

        Each element in the array is one ActionTrail event dict.
        """
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            batch = json.loads(text)
            if not isinstance(batch, list):
                batch = [batch]

            for event in batch:
                if not isinstance(event, dict):
                    continue

                # Skip read-only operations (list/get/describe)
                event_name = event.get("eventName", "")
                if not event_name:
                    continue
                lower_name = event_name.lower()
                if any(lower_name.startswith(p) for p in (
                    "get", "list", "describe", "query", "check", "validate",
                    "preview", "fetch", "lookup",
                )):
                    continue

                user = event.get("userIdentity") or {}
                if not isinstance(user, dict):
                    user = {}

                error_code = event.get("errorCode") or ""
                outcome = "failure" if error_code else "success"

                record = {
                    # Core event fields
                    "eventId":        event.get("eventId", ""),
                    "eventName":      event_name,
                    "eventTime":      event.get("eventTime", ""),
                    "region":         event.get("region", ""),
                    "requestId":      event.get("requestId", ""),
                    # Normalized fields (used directly by field mapping + rule evaluator)
                    "service":        (event.get("serviceName") or "").lower(),
                    "operation":      event_name,
                    "outcome":        outcome,
                    "error_code":     error_code,
                    # Actor
                    "user_type":      user.get("type", ""),
                    "user_username":  user.get("userName", user.get("principalId", "")),
                    "user_accountId": user.get("accountId", ""),
                    "user_accessKey": user.get("accessKeyId", ""),
                    # Network
                    "sourceIpAddress": event.get("sourceIpAddress", ""),
                    "userAgent":       event.get("userAgent", ""),
                    # Payloads (for advanced conditions via raw_event fallback)
                    "requestParameters": json.dumps(event.get("requestParameters") or {}),
                    "responseElements":  json.dumps(event.get("responseElements") or {}),
                    "additionalEventData": json.dumps(event.get("additionalEventData") or {}),
                }
                yield record

        except Exception as exc:
            logger.debug(f"ActionTrail parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_time":      "eventTime",
            "operation":       "operation",
            "service":         "service",
            "outcome":         "outcome",
            "error_code":      "error_code",
            "actor.principal": "user_username",
            "actor.ip_address": "sourceIpAddress",
            "actor.account_id": "user_accountId",
            "resource.region": "region",
        }

    def get_event_category(self) -> str:
        return EventCategory.API_ACTIVITY
