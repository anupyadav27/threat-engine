"""
Azure NSG Flow Log v2 parser — nested JSON with flow tuples.

NSG Flow Logs are the Azure equivalent of AWS VPC Flow Logs. They record
network flows allowed or denied by Network Security Group rules.

Input format (v2):
{
  "records": [{
    "time": "2026-03-28T10:00:00Z",
    "systemId": "xxx",
    "macAddress": "xxx",
    "category": "NetworkSecurityGroupFlowEvent",
    "operationName": "NetworkSecurityGroupFlowEvents",
    "properties": {
      "Version": 2,
      "flows": [{
        "rule": "DefaultRule_AllowInternetOutBound",
        "flows": [{
          "mac": "xxx",
          "flowTuples": [
            "timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,action,flowState,pktsSrc,bytesSrc,pktsDst,bytesDst"
          ]
        }]
      }]
    }
  }]
}

Flow tuple fields (v2, 13 fields):
  0: Unix timestamp
  1: Source IP
  2: Destination IP
  3: Source port
  4: Destination port
  5: Protocol (T=TCP, U=UDP)
  6: Direction (I=Inbound, O=Outbound)
  7: Action (A=Allow, D=Deny)
  8: Flow state (B=Begin, C=Continue, E=End)
  9: Packets (source to destination)
  10: Bytes (source to destination)
  11: Packets (destination to source)
  12: Bytes (destination to source)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

_PROTOCOL_MAP = {"T": "tcp", "U": "udp"}
_DIRECTION_MAP = {"I": "inbound", "O": "outbound"}
_ACTION_MAP = {"A": "A", "D": "D"}  # Keep short for rule matching
_FLOW_STATE_MAP = {"B": "begin", "C": "continue", "E": "end"}


def _parse_flow_tuple(tuple_str: str, rule_name: str, record_time: str) -> Dict[str, Any]:
    """Parse a single flow tuple string into a dict.

    Args:
        tuple_str: Comma-separated flow tuple.
        rule_name: NSG rule that matched this flow.
        record_time: Timestamp from the parent record.

    Returns:
        Dict with parsed flow fields, or empty dict on parse error.
    """
    parts = tuple_str.split(",")
    if len(parts) < 8:
        return {}

    result = {
        "rule_name": rule_name,
        "record_time": record_time,
        "srcaddr": parts[1],
        "dstaddr": parts[2],
        "srcport": parts[3],
        "dstport": parts[4],
        "protocol_name": _PROTOCOL_MAP.get(parts[5], parts[5]),
        "direction": _DIRECTION_MAP.get(parts[6], parts[6]),
        "action": _ACTION_MAP.get(parts[7], parts[7]),
    }

    # Parse unix timestamp
    try:
        ts = int(parts[0])
        result["event_time"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        result["event_time"] = record_time

    # v2 extended fields (flow state + byte/packet counts)
    if len(parts) >= 13:
        result["flow_state"] = _FLOW_STATE_MAP.get(parts[8], parts[8])
        result["packets_src"] = parts[9] if parts[9] != "0" else "0"
        result["bytes_src"] = parts[10] if parts[10] != "0" else "0"
        result["packets_dst"] = parts[11] if parts[11] != "0" else "0"
        result["bytes_dst"] = parts[12] if parts[12] != "0" else "0"

    return result


class AzureNSGFlowParser(BaseParser):
    """Parses Azure NSG Flow Log v2 JSON into individual flow records."""

    format_name = "azure_nsg_flow"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse raw bytes and yield individual flow records.

        Args:
            raw_bytes: Decompressed NSG Flow Log JSON content.

        Yields:
            Dict representing one network flow with flattened fields.
        """
        try:
            data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.debug("Azure NSG Flow parse error: %s", exc)
            return

        records = []
        if isinstance(data, dict):
            records = data.get("records", [])
        elif isinstance(data, list):
            records = data

        for record in records:
            record_time = record.get("time", "")
            system_id = record.get("systemId", "")
            mac_address = record.get("macAddress", "")
            properties = record.get("properties", {})
            nsg_flows = properties.get("flows", [])

            for flow_group in nsg_flows:
                rule_name = flow_group.get("rule", "")
                inner_flows = flow_group.get("flows", [])

                for inner in inner_flows:
                    flow_mac = inner.get("mac", mac_address)
                    tuples = inner.get("flowTuples", [])

                    for tuple_str in tuples:
                        parsed = _parse_flow_tuple(tuple_str, rule_name, record_time)
                        if not parsed:
                            continue

                        # Attach parent metadata
                        parsed["system_id"] = system_id
                        parsed["mac_address"] = flow_mac
                        parsed["nsg_rule"] = rule_name

                        yield parsed

    def get_field_mapping(self) -> Dict[str, str]:
        """Return mapping from NormalizedEvent field path to source field name.

        Returns:
            Dict mapping normalized network fields to parsed flow fields.
        """
        return {
            "network.src_ip": "srcaddr",
            "network.dst_ip": "dstaddr",
            "network.src_port": "srcport",
            "network.dst_port": "dstport",
            "network.protocol": "protocol_name",
            "network.direction": "direction",
            "network.flow_action": "action",
            "network.bytes_in": "bytes_src",
            "network.bytes_out": "bytes_dst",
            "network.packets": "packets_src",
        }

    def get_event_category(self) -> str:
        """Return EventCategory for NSG Flow Log events.

        Returns:
            EventCategory.NETWORK_ACTIVITY for network flow data.
        """
        return EventCategory.NETWORK_ACTIVITY
