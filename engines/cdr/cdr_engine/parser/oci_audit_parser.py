"""OCI Audit Log parser — nested JSON with data.eventType structure.

OCI Audit logs wrap each event in a `data` envelope:
{
  "data": {
    "eventType": "com.oraclecloud.computeapi.LaunchInstance",
    "source": "computeapi",
    "eventTime": "2026-03-28T10:00:00Z",
    "identity": {...},
    "request": {...},
    "response": {...},
    "stateChange": {...},
    "additionalDetails": {...},
    "resourceId": "ocid1.instance.xxx",
    "compartmentId": "ocid1.compartment.xxx"
  }
}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class OCIAuditParser(BaseParser):
    """Parser for OCI Audit Log JSON events."""

    format_name = "oci_audit"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse OCI Audit log bytes into individual event dicts.

        Handles both single-event JSON and JSON-lines (one event per line).
        The nested `data` envelope is unwrapped so downstream consumers
        get a flat-ish dict with the important fields at top level.

        Args:
            raw_bytes: Decompressed file content

        Yields:
            Dict representing one OCI Audit event
        """
        try:
            text = raw_bytes.decode("utf-8", errors="replace").strip()
            if not text:
                return

            # Try parsing as a single JSON object or array first
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    for item in parsed:
                        event = self._extract_event(item)
                        if event:
                            yield event
                    return
                elif isinstance(parsed, dict):
                    event = self._extract_event(parsed)
                    if event:
                        yield event
                    return
            except json.JSONDecodeError:
                pass

            # Fall back to JSON-lines (one JSON object per line)
            for line in text.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    event = self._extract_event(parsed)
                    if event:
                        yield event
                except json.JSONDecodeError:
                    continue

        except Exception as exc:
            logger.debug(f"OCI Audit parse error: {exc}")

    def _extract_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Unwrap the OCI data envelope and normalize key fields.

        Args:
            raw: Raw JSON dict (may have top-level `data` key)

        Returns:
            Flattened event dict with _service and _operation helpers
        """
        # Support both formats:
        #   camelCase (Object Storage): {"data": {"eventType": ..., "identity": ..., ...}}
        #   snake_case (direct API):    {"event_type": ..., "source": ..., "data": {"identity": ..., ...}}
        inner = raw.get("data") or {}
        if isinstance(inner, dict):
            data = inner
        else:
            data = {}

        def _get(*dicts_and_keys):
            """Try each (dict, key) pair; return first non-empty value."""
            for d, *keys in dicts_and_keys:
                for k in keys:
                    v = d.get(k)
                    if v:
                        return v
            return ""

        # Extract eventType — top-level in direct API, inside data in OS logs
        event_type = _get(
            (data, "eventType"),
            (raw,  "event_type", "eventType"),
        )
        parts = event_type.rsplit(".", 1)
        operation = parts[-1] if len(parts) > 1 else event_type

        # Source — top-level in both formats
        source_val = raw.get("source") or data.get("source", "")

        # Extract service from eventType or source
        service = ".".join(parts[:-1]).lower() if len(parts) > 1 else source_val.lower()

        identity = data.get("identity") or {}
        request = data.get("request") or {}
        response = data.get("response") or {}

        # Derive outcome from HTTP response status
        status_str = response.get("status", "")
        try:
            status_code = int(status_str)
            _outcome = "success" if 200 <= status_code < 300 else "failure"
        except (ValueError, TypeError):
            _outcome = "unknown"

        return {
            # Core fields
            "eventType": event_type,
            "_service": service,
            "_operation": operation,
            "_outcome": _outcome,
            "source": source_val,
            "eventTime": _get((data, "eventTime"), (raw, "event_time", "eventTime")),

            # Actor / identity (camelCase from OS logs; snake_case from direct API)
            "principalId": identity.get("principalId") or identity.get("principal_id", ""),
            "principalName": identity.get("principalName") or identity.get("principal_name", ""),
            "ipAddress": identity.get("ipAddress") or identity.get("ip_address", ""),
            "tenantId": identity.get("tenantId") or identity.get("tenant_id", ""),
            "userAgent": identity.get("userAgent") or identity.get("user_agent", ""),
            "credentials": identity.get("credentials", {}),

            # Request
            "requestAction": request.get("action", ""),
            "requestId": request.get("id", ""),
            "requestPath": request.get("path", ""),
            "requestParameters": request.get("parameters", {}),

            # Response
            "responseStatus": response.get("status", ""),
            "responseTime": response.get("responseTime") or response.get("response_time", ""),
            "responseHeaders": response.get("headers", {}),

            # Resource
            "resourceId": _get((data, "resourceId", "resource_id"), (raw, "resource_id")),
            "compartmentId": _get((data, "compartmentId", "compartment_id"), (raw, "compartment_id")),

            # State change
            "stateChange": data.get("stateChange", {}),
            "additionalDetails": data.get("additionalDetails", {}),

            # Keep raw for rule evaluation
            "_raw": data,
        }

    def get_field_mapping(self) -> Dict[str, str]:
        """Map OCI Audit fields to NormalizedEvent fields.

        Returns:
            Mapping from NormalizedEvent path to OCI event key
        """
        return {
            "service": "_service",
            "operation": "_operation",
            "outcome": "_outcome",  # "success" / "failure" derived from HTTP response status
            "actor.principal": "principalId",
            "actor.principal_type": "principalName",
            "actor.ip_address": "ipAddress",
            "actor.user_agent": "userAgent",
            "actor.account_id": "tenantId",
            "resource.uid": "resourceId",
            "resource.region": "source",
        }

    def get_event_category(self) -> str:
        """OCI Audit events are API activity."""
        return EventCategory.API_ACTIVITY
