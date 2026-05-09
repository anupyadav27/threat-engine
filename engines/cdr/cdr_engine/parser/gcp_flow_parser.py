"""
GCP VPC Flow Log parser.

GCP exports VPC Flow Logs as JSON (to GCS sink or BigQuery).
Each record is a JSON object with:
  jsonPayload.connection.{src_ip, dst_ip, src_port, dst_port, protocol}
  jsonPayload.bytes_sent
  jsonPayload.packets_sent
  jsonPayload.start_time / end_time
  jsonPayload.reporter           — "SRC" or "DEST"
  jsonPayload.src_instance.{project_id, vm_name, zone}
  jsonPayload.dest_instance.{project_id, vm_name, zone}
  resource.labels.{subnetwork_name, project_id}
  timestamp

Supports JSON array or JSON-lines format.
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

# IANA protocol numbers → names
_PROTOCOL_MAP = {6: "tcp", 17: "udp", 1: "icmp", "6": "tcp", "17": "udp", "1": "icmp"}


class GCPFlowParser(BaseParser):
    """Parse GCP VPC Flow Log JSON records."""

    format_name = "gcp_vpc_flow"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse raw bytes as JSON array or JSON-lines.

        Yields flat dicts with network.* keys suitable for rule evaluation.
        """
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            return

        for record in self._load_records(text):
            try:
                flat = self._flatten(record)
                if flat is not None:
                    yield flat
            except Exception as exc:
                logger.debug(f"GCP flow record parse error: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_records(text: str) -> Generator[Dict[str, Any], None, None]:
        """Try JSON array first, then fall back to JSON-lines."""
        if text.startswith("["):
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    yield from data
                    return
            except json.JSONDecodeError:
                pass

        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    @staticmethod
    def _flatten(record: Dict[str, Any]) -> Dict[str, Any] | None:
        """Extract connection fields into a flat dict."""
        payload = record.get("jsonPayload")
        if payload is None:
            return None

        conn = payload.get("connection", {})
        if not conn:
            return None

        protocol_raw = conn.get("protocol", "")
        protocol_name = _PROTOCOL_MAP.get(protocol_raw, str(protocol_raw))

        src_instance = payload.get("src_instance", {})
        dest_instance = payload.get("dest_instance", {})
        resource_labels = record.get("resource", {}).get("labels", {})

        return {
            # Network fields (match rule conditions)
            "src_ip": conn.get("src_ip", ""),
            "dst_ip": conn.get("dst_ip", ""),
            "src_port": str(conn.get("src_port", "")),
            "dst_port": str(conn.get("dst_port", "")),
            "protocol": protocol_raw,
            "protocol_name": protocol_name,
            "bytes_sent": str(payload.get("bytes_sent", "0")),
            "packets_sent": str(payload.get("packets_sent", "0")),
            "start_time": payload.get("start_time", ""),
            "end_time": payload.get("end_time", ""),
            "reporter": payload.get("reporter", ""),
            # Instance metadata
            "src_vm": src_instance.get("vm_name", ""),
            "src_zone": src_instance.get("zone", ""),
            "src_project": src_instance.get("project_id", ""),
            "dst_vm": dest_instance.get("vm_name", ""),
            "dst_zone": dest_instance.get("zone", ""),
            "dst_project": dest_instance.get("project_id", ""),
            # Resource labels
            "project_id": resource_labels.get("project_id", ""),
            "subnetwork": resource_labels.get("subnetwork_name", ""),
            # Timestamp
            "timestamp": record.get("timestamp", ""),
            # Keep original for deep inspection
            "_raw": record,
        }

    # ------------------------------------------------------------------
    # BaseParser interface
    # ------------------------------------------------------------------

    def get_field_mapping(self) -> Dict[str, str]:
        """Map normalised event field paths to flat record keys."""
        return {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.src_port": "src_port",
            "network.dst_port": "dst_port",
            "network.protocol": "protocol_name",
            "network.bytes_out": "bytes_sent",
            "network.packets": "packets_sent",
            "network.flow_action": "reporter",  # SRC/DEST (GCP doesn't have ACCEPT/REJECT in flow)
            "resource.account_id": "project_id",
            "timestamp": "timestamp",
        }

    def get_event_category(self) -> str:
        return EventCategory.NETWORK_ACTIVITY
