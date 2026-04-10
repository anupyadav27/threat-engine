"""IBM Cloud Activity Tracker parser — CADF (Cloud Auditing Data Federation) JSON.

IBM Activity Tracker events follow the CADF standard:
{
  "action": "is.instance.instance.create",
  "outcome": "success",
  "initiator": {"id": "IBMid-xxx", "name": "user@company.com", "host": {"address": "1.2.3.4"}},
  "target": {"id": "crn:v1:...", "typeURI": "is.instance/instance", "name": "my-instance"},
  "eventTime": "2026-03-28T10:00:00.000Z",
  "severity": "warning",
  "requestData": {...},
  "responseData": {...},
  "reason": {"reasonCode": 201, "reasonType": "Created"}
}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class IBMActivityParser(BaseParser):
    """Parser for IBM Cloud Activity Tracker CADF events."""

    format_name = "ibm_activity"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse IBM Activity Tracker bytes into individual event dicts.

        Handles JSON array, single JSON object, and JSON-lines formats.

        Args:
            raw_bytes: Decompressed file content

        Yields:
            Dict representing one IBM CADF event with normalized helper fields
        """
        try:
            text = raw_bytes.decode("utf-8", errors="replace").strip()
            if not text:
                return

            # Try single JSON object or array
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    for item in parsed:
                        event = self._normalize_event(item)
                        if event:
                            yield event
                    return
                elif isinstance(parsed, dict):
                    # Could be a wrapper with "events" key
                    events = parsed.get("events", [parsed])
                    for item in events:
                        event = self._normalize_event(item)
                        if event:
                            yield event
                    return
            except json.JSONDecodeError:
                pass

            # Fall back to JSON-lines
            for line in text.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    event = self._normalize_event(parsed)
                    if event:
                        yield event
                except json.JSONDecodeError:
                    continue

        except Exception as exc:
            logger.debug(f"IBM Activity parse error: {exc}")

    def _normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map CADF fields to a flat dict for rule evaluation.

        Args:
            raw: Raw CADF JSON dict

        Returns:
            Flattened event dict with _service, _operation, and actor fields
        """
        action = raw.get("action", "")

        # Parse CADF action: "is.instance.instance.create"
        # Convention: <service>.<resource>.<sub-resource>.<verb>
        # Extract service (first segment) and operation verb (last segment)
        action_parts = action.split(".")
        service = action_parts[0] if action_parts else ""
        operation_verb = action_parts[-1] if action_parts else ""

        initiator = raw.get("initiator", {})
        target = raw.get("target", {})
        reason = raw.get("reason", {})
        observer = raw.get("observer", {})
        host = initiator.get("host", {})

        # Determine outcome from CADF outcome field
        outcome = raw.get("outcome", "unknown")
        if outcome not in ("success", "failure"):
            # Derive from reason code
            reason_code = reason.get("reasonCode", 0)
            if isinstance(reason_code, int):
                if 200 <= reason_code < 300:
                    outcome = "success"
                elif reason_code >= 400:
                    outcome = "failure"

        # Extract account from target CRN: crn:v1:bluemix:public:is:us-south:a/<account>::...
        account_id = ""
        target_id = target.get("id", "")
        if target_id.startswith("crn:"):
            crn_parts = target_id.split(":")
            if len(crn_parts) >= 7:
                scope = crn_parts[6]  # a/<account_id> or s/<scope_id>
                if scope.startswith("a/"):
                    account_id = scope[2:]

        # Extract region from CRN
        region = ""
        if target_id.startswith("crn:"):
            crn_parts = target_id.split(":")
            if len(crn_parts) >= 6:
                region = crn_parts[5]

        return {
            # Core
            "action": action,
            "_service": service,
            "_operation": operation_verb,
            "eventTime": raw.get("eventTime", ""),
            "outcome": outcome,
            "severity": raw.get("severity", ""),

            # Actor / initiator
            "initiatorId": initiator.get("id", ""),
            "initiatorName": initiator.get("name", ""),
            "initiatorType": initiator.get("typeURI", ""),
            "ipAddress": host.get("address", ""),
            "userAgent": host.get("agent", ""),
            "credential": initiator.get("credential", {}),

            # Target
            "targetId": target_id,
            "targetName": target.get("name", ""),
            "targetTypeURI": target.get("typeURI", ""),
            "accountId": account_id,
            "region": region,

            # Reason
            "reasonCode": reason.get("reasonCode", 0),
            "reasonType": reason.get("reasonType", ""),

            # Data payloads
            "requestData": raw.get("requestData", {}),
            "responseData": raw.get("responseData", {}),

            # Observer
            "observerName": observer.get("name", ""),

            # Keep raw for rule evaluation
            "_raw": raw,
        }

    def get_field_mapping(self) -> Dict[str, str]:
        """Map IBM CADF fields to NormalizedEvent fields.

        Returns:
            Mapping from NormalizedEvent path to IBM event key
        """
        return {
            "service": "_service",
            "operation": "action",
            "actor.principal": "initiatorId",
            "actor.principal_type": "initiatorType",
            "actor.ip_address": "ipAddress",
            "actor.user_agent": "userAgent",
            "actor.account_id": "accountId",
            "resource.uid": "targetId",
            "resource.name": "targetName",
            "resource.resource_type": "targetTypeURI",
            "resource.region": "region",
        }

    def get_event_category(self) -> str:
        """IBM Activity Tracker events are API activity."""
        return EventCategory.API_ACTIVITY
