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

                req_params = event.get("requestParameters") or {}
                if isinstance(req_params, str):
                    try:
                        req_params = json.loads(req_params)
                    except Exception:
                        req_params = {}

                resp_elems = event.get("responseElements") or {}
                if isinstance(resp_elems, str):
                    try:
                        resp_elems = json.loads(resp_elems)
                    except Exception:
                        resp_elems = {}

                # Extract AliCloud resource ARN (acs: prefix) from common fields.
                # AliCloud ARNs look like: arn:acs:ram::123456:role/admin
                # Also check referencedResources array (similar to AWS resources[])
                _resource_uid = ""
                for arn_field in ("Arn", "arn", "ResourceArn", "resourceArn", "RoleArn"):
                    val = req_params.get(arn_field) or resp_elems.get(arn_field)
                    if val and isinstance(val, str) and (
                        val.startswith("arn:acs:") or val.startswith("acs:")
                    ):
                        _resource_uid = val
                        break
                # Fallback: referencedResources array (some ActionTrail events)
                if not _resource_uid:
                    refs = event.get("referencedResources") or []
                    if isinstance(refs, list) and refs and isinstance(refs[0], dict):
                        _resource_uid = refs[0].get("ARN", refs[0].get("arn", ""))

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
                    # Resource UID (AliCloud ARN or empty — suffix-match fallback handles rest)
                    "_resource_uid":  _resource_uid,
                    # Keep as dicts so _step3_flatten() can extract additional IDs
                    "requestParameters":   req_params,
                    "responseElements":    resp_elems,
                    "additionalEventData": event.get("additionalEventData") or {},
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
            "resource.uid":    "_resource_uid",
            "resource.region": "region",
        }

    def get_event_category(self) -> str:
        return EventCategory.API_ACTIVITY
