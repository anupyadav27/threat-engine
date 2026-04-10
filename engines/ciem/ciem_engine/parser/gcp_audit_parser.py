"""
GCP Cloud Audit Log parser.

Handles two export formats:
  - JSON array (BigQuery export or aggregated files)
  - JSON Lines / newline-delimited JSON (GCS log sink export)

Source schema:
  protoPayload.serviceName      → service
  protoPayload.methodName       → operation
  protoPayload.authenticationInfo.principalEmail → actor.principal
  protoPayload.requestMetadata.callerIp          → actor.ip_address
  protoPayload.requestMetadata.callerSuppliedUserAgent → actor.user_agent
  protoPayload.resourceName     → resource.uid
  protoPayload.status.code      → outcome  (0 = success)
  resource.labels.project_id    → resource.account_id
  timestamp                     → timestamp
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

# GCP gRPC status codes — 0 is OK, everything else is a failure
_SUCCESS_CODES = {0, "0"}


class GCPAuditParser(BaseParser):
    """Parse GCP Cloud Audit Log JSON (Admin Activity + Data Access)."""

    format_name = "gcp_audit"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse raw bytes as JSON array or JSON-lines.

        Yields one dict per audit log entry with helper fields:
            _service   — short service name (e.g. 'compute')
            _operation — full methodName
            _actor     — principalEmail
            _ip        — callerIp
            _user_agent — callerSuppliedUserAgent
            _resource  — resourceName
            _project   — project_id from resource labels
            _outcome   — 'success' | 'failure'
        """
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            return

        records = self._load_records(text)
        for record in records:
            try:
                enriched = self._enrich(record)
                if enriched is not None:
                    yield enriched
            except Exception as exc:
                logger.debug(f"GCP audit record parse error: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_records(text: str) -> Generator[Dict[str, Any], None, None]:
        """Try JSON array first, then fall back to JSON-lines."""
        # JSON array (starts with '[')
        if text.startswith("["):
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    yield from data
                    return
            except json.JSONDecodeError:
                pass

        # JSON-lines (one JSON object per line)
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    @staticmethod
    def _enrich(record: Dict[str, Any]) -> Dict[str, Any] | None:
        """Add convenience fields from the nested protoPayload."""
        proto = record.get("protoPayload")
        if proto is None:
            return None

        service_name = proto.get("serviceName", "")
        # Shorten: compute.googleapis.com → compute
        short_service = service_name.replace(".googleapis.com", "") if service_name else ""

        auth_info = proto.get("authenticationInfo", {})
        req_meta = proto.get("requestMetadata", {})
        status = proto.get("status", {})
        resource_labels = record.get("resource", {}).get("labels", {})

        # Determine outcome from gRPC status code
        code = status.get("code") if isinstance(status, dict) else None
        outcome = "success" if code in _SUCCESS_CODES else "failure"
        # Absent status also treated as success (Admin Activity logs omit it on success)
        if not status or code is None:
            outcome = "success"

        record["_service"] = short_service
        record["_operation"] = proto.get("methodName", "")
        record["_actor"] = auth_info.get("principalEmail", "")
        record["_ip"] = req_meta.get("callerIp", "")
        record["_user_agent"] = req_meta.get("callerSuppliedUserAgent", "")
        record["_resource"] = proto.get("resourceName", "")
        record["_project"] = resource_labels.get("project_id", "")
        record["_outcome"] = outcome

        return record

    # ------------------------------------------------------------------
    # BaseParser interface
    # ------------------------------------------------------------------

    def get_field_mapping(self) -> Dict[str, str]:
        """Map normalised event field paths to enriched record keys."""
        return {
            "service": "_service",
            "operation": "_operation",
            "actor.principal": "_actor",
            "actor.ip_address": "_ip",
            "actor.user_agent": "_user_agent",
            "resource.uid": "_resource",
            "resource.account_id": "_project",
            "outcome": "_outcome",
            "timestamp": "timestamp",
        }

    def get_event_category(self) -> str:
        return EventCategory.API_ACTIVITY
