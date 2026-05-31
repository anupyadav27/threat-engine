"""
Azure Monitor Activity Log reader — reads directly from the Azure Monitor REST API.

Skips blob storage entirely. Uses azure-mgmt-monitor SDK to query the activity
log API, which is available immediately with no delivery delay.

Source type:  azure_activity
Storage type: azure_monitor
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Generator, Dict, List

from .base_reader import BaseReader, LogSource

logger = logging.getLogger(__name__)


class AzureMonitorReader(BaseReader):
    """Read Azure Activity Logs directly from the Azure Monitor API."""

    storage_type = "azure_monitor"

    def list_log_files(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        """Azure Monitor API returns events directly — no file listing needed."""
        # Return a single pseudo-file entry representing the API query window
        return [{"key": f"azure_monitor:{start_time.isoformat()}/{end_time.isoformat()}", "size": 0, "last_modified": end_time}]

    def read(
        self,
        session: Any,
        source: LogSource,
        start_time: datetime,
        end_time: datetime,
        max_bytes: int = 500_000_000,
    ) -> Generator[bytes, None, None]:
        """Yield batches of Azure Activity Log events as JSON lines.

        Args:
            session: Azure credential (ClientSecretCredential or DefaultAzureCredential)
            source: LogSource with account_id = subscription_id
            start_time: Start of collection window
            end_time: End of collection window
        """
        subscription_id = source.account_id
        if not subscription_id:
            logger.warning("AzureMonitorReader: no subscription_id in source.account_id")
            return

        try:
            from azure.mgmt.monitor import MonitorManagementClient
        except ImportError:
            logger.warning("azure-mgmt-monitor not installed — falling back to REST")
            yield from self._read_via_rest(session, subscription_id, start_time, end_time)
            return

        try:
            client = MonitorManagementClient(credential=session, subscription_id=subscription_id)

            # Azure Monitor filter format
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str   = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_str = f"eventTimestamp ge '{start_str}' and eventTimestamp le '{end_str}'"

            events = client.activity_logs.list(filter=filter_str)

            batch = []
            total_bytes = 0
            for event in events:
                record = self._event_to_dict(event)
                line = json.dumps(record)
                batch.append(line)
                total_bytes += len(line)

                if total_bytes >= max_bytes:
                    logger.warning("AzureMonitorReader: hit max_bytes limit")
                    break

                if len(batch) >= 1000:
                    yield ("\n".join(batch) + "\n").encode()
                    batch = []

            if batch:
                yield ("\n".join(batch) + "\n").encode()

            logger.info(
                f"AzureMonitorReader: fetched {total_bytes} bytes of activity logs "
                f"for subscription={subscription_id} "
                f"window={start_str} → {end_str}"
            )

        except Exception as exc:
            logger.error(f"AzureMonitorReader failed: {exc}", exc_info=True)

    def _event_to_dict(self, event: Any) -> dict:
        """Convert azure-mgmt-monitor EventData to a plain dict."""
        def _str(v):
            return str(v) if v is not None else None

        caller = getattr(event, "caller", None)
        op = getattr(event, "operation_name", None)
        status = getattr(event, "status", None)
        sub = getattr(event, "subscription_id", None)
        ts = getattr(event, "event_timestamp", None)
        resource_id = getattr(event, "resource_id", None)
        resource_type = getattr(event, "resource_type", None)
        resource_group = getattr(event, "resource_group_name", None)
        level = getattr(event, "level", None)
        http = getattr(event, "http_request", None)
        properties = getattr(event, "properties", None)

        return {
            "eventTimestamp":    ts.isoformat() if ts else None,
            "caller":            caller,
            "operationName":     _str(getattr(op, "value", op)),
            "operationNameLocalizedValue": _str(getattr(op, "localized_value", None)),
            "status":            _str(getattr(status, "value", status)),
            "subscriptionId":    sub,
            "resourceId":        resource_id,
            "resourceType":      _str(getattr(resource_type, "value", resource_type)),
            "resourceGroupName": resource_group,
            "level":             _str(level),
            "clientIpAddress":   getattr(http, "client_ip_address", None) if http else None,
            "httpMethod":        getattr(http, "method", None) if http else None,
            "properties":        dict(properties) if properties else {},
            "category":          _str(getattr(getattr(event, "category", None), "value", None)),
            "correlationId":     getattr(event, "correlation_id", None),
            "eventDataId":       getattr(event, "event_data_id", None),
        }

    def _read_via_rest(
        self,
        session: Any,
        subscription_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Generator[bytes, None, None]:
        """Fallback: read via raw Azure Monitor REST API using the credential token."""
        import urllib.request as _req

        try:
            token = session.get_token("https://management.azure.com/.default").token
        except Exception as exc:
            logger.error(f"Could not get Azure token: {exc}")
            return

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str   = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = f"eventTimestamp ge '{start_str}' and eventTimestamp le '{end_str}'"

        import urllib.parse
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Insights/eventtypes/management/values"
            f"?api-version=2015-04-01&$filter={urllib.parse.quote(filter_str)}"
        )

        total = 0
        while url:
            req = _req.Request(url, headers={"Authorization": f"Bearer {token}"})
            try:
                with _req.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                events = data.get("value", [])
                if events:
                    normalized = [self._normalize_rest_event(e) for e in events]
                    total += len(normalized)
                    yield ("\n".join(json.dumps(e) for e in normalized) + "\n").encode()
                url = data.get("nextLink")
            except Exception as exc:
                logger.error(f"Azure Monitor REST call failed: {exc}")
                break
        logger.info(f"AzureMonitorReader (REST): fetched {total} events for subscription={subscription_id}")

    def _normalize_rest_event(self, event: dict) -> dict:
        """Normalize Azure Monitor REST API event to match SDK _event_to_dict format.

        The REST API returns nested dicts for operationName, status, resourceType, etc.
        (e.g. {"value": "Microsoft.Compute/...", "localizedValue": "..."}).
        The SDK objects are already extracted to plain strings by _event_to_dict.
        """
        def _str_val(v: Any) -> Any:
            if isinstance(v, dict):
                return v.get("value") or v.get("localizedValue")
            return v

        http = event.get("httpRequest") if isinstance(event.get("httpRequest"), dict) else {}
        op = event.get("operationName", {})
        return {
            "eventTimestamp":             event.get("eventTimestamp"),
            "caller":                     event.get("caller"),
            "operationName":              _str_val(op),
            "operationNameLocalizedValue": op.get("localizedValue") if isinstance(op, dict) else None,
            "status":                     _str_val(event.get("status")),
            "subscriptionId":             event.get("subscriptionId"),
            "resourceId":                 event.get("resourceId"),
            "resourceType":               _str_val(event.get("resourceType")),
            "resourceGroupName":          event.get("resourceGroupName"),
            "level":                      _str_val(event.get("level")),
            "clientIpAddress":            http.get("clientIpAddress"),
            "httpMethod":                 http.get("method"),
            "properties":                 event.get("properties") or {},
            "category":                   _str_val(event.get("category")),
            "correlationId":              event.get("correlationId"),
            "eventDataId":                event.get("eventDataId"),
        }
