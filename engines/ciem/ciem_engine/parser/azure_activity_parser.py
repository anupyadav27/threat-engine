"""
Azure Activity Log parser — JSON array or JSON-lines format.

Azure Activity Log records all Azure Resource Manager operations. Each event
contains operationName, caller, callerIpAddress, resourceId, status, etc.

Supports two input formats:
  1. JSON array: {"records": [{event}, ...]}   (Azure diagnostic export)
  2. JSON lines: one event per line             (streaming / EventHub)
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


def _extract_resource_type(resource_id: str) -> str:
    """Extract Azure resource type from resourceId.

    Args:
        resource_id: Full ARM resource ID, e.g.
            /subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1

    Returns:
        Provider-qualified type like 'Microsoft.Compute/virtualMachines',
        or empty string if parsing fails.
    """
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        idx = parts.index("providers")
        # providers/Microsoft.Compute/virtualMachines/vm1 → Microsoft.Compute/virtualMachines
        if idx + 2 < len(parts):
            return f"{parts[idx + 1]}/{parts[idx + 2]}"
    except ValueError:
        pass
    return ""


def _extract_subscription_id(resource_id: str) -> str:
    """Extract subscription ID from resourceId.

    Args:
        resource_id: Full ARM resource ID.

    Returns:
        Subscription UUID or empty string.
    """
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        idx = parts.index("subscriptions")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    except ValueError:
        pass
    return ""


def _map_status(event: Dict[str, Any]) -> str:
    """Map Azure status to normalized outcome string.

    Azure uses several locations for status:
      - status.value: "Succeeded", "Failed", "Started", "Accepted"
      - resultType: "Success", "Failure"
      - properties.statusCode: HTTP status codes
    """
    # Try status.value first
    status_obj = event.get("status")
    if isinstance(status_obj, dict):
        val = status_obj.get("value", "").lower()
        if val in ("succeeded", "success", "accepted"):
            return "success"
        if val in ("failed", "failure"):
            return "failure"
        if val:
            return val

    # Fallback to resultType
    result_type = event.get("resultType", "").lower()
    if result_type in ("success",):
        return "success"
    if result_type in ("failure",):
        return "failure"

    return "unknown"


class AzureActivityParser(BaseParser):
    """Parses Azure Activity Log events from JSON."""

    format_name = "azure_activity"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse raw bytes into individual Azure Activity Log events.

        Args:
            raw_bytes: Decompressed file content (JSON array or JSON lines).

        Yields:
            Dict representing one Azure Activity Log event with added
            helper fields prefixed with underscore.
        """
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            return

        # Try JSON array format first ({"records": [...]})
        events = self._try_json_array(text)
        if events is None:
            # Fallback to JSON lines (one event per line)
            events = self._try_json_lines(text)

        for event in events:
            resource_id = event.get("resourceId", "")
            event["_resource_type"] = _extract_resource_type(resource_id)
            event["_subscription_id"] = _extract_subscription_id(resource_id)
            event["_outcome"] = _map_status(event)

            # Extract service from operationName: Microsoft.Compute/... → Compute
            op_name = event.get("operationName", "")
            if op_name.startswith("Microsoft."):
                parts = op_name.split("/")
                event["_service"] = parts[0].replace("Microsoft.", "").lower()
            else:
                event["_service"] = ""

            yield event

    def _try_json_array(self, text: str) -> list:
        """Attempt to parse as a JSON object with a 'records' array.

        Returns:
            List of event dicts, or None if not in this format.
        """
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                records = data.get("records", data.get("value", []))
                if isinstance(records, list):
                    return records
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return None

    def _try_json_lines(self, text: str) -> Generator[Dict[str, Any], None, None]:
        """Parse JSON lines format (one JSON object per line).

        Yields:
            Individual event dicts.
        """
        for line_num, line in enumerate(text.split("\n"), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    yield event
            except json.JSONDecodeError:
                logger.debug(
                    "Azure Activity parse error on line %d: invalid JSON", line_num
                )

    def get_field_mapping(self) -> Dict[str, str]:
        """Return mapping from NormalizedEvent field path to source field name.

        Returns:
            Dict mapping normalized field names to Azure Activity Log field names.
        """
        return {
            "event_id": "correlationId",
            "operation": "operationName",
            "actor.principal": "caller",
            "actor.ip_address": "callerIpAddress",
            "resource.uid": "resourceId",
            "resource.resource_type": "_resource_type",
            "resource.account_id": "_subscription_id",
            "service": "_service",
            "outcome": "_outcome",
        }

    def get_event_category(self) -> str:
        """Return EventCategory for Azure Activity Log events.

        Returns:
            EventCategory.API_ACTIVITY since Activity Log records ARM operations.
        """
        return EventCategory.API_ACTIVITY
