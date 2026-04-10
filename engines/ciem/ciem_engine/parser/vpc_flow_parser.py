"""
VPC Flow Log parser — space-delimited text.

Format (v2): version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
Format (v5+): adds vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr
"""

import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

# Default v2 field order
_V2_FIELDS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status",
]

_PROTOCOL_MAP = {"6": "tcp", "17": "udp", "1": "icmp"}


class VPCFlowParser(BaseParser):
    format_name = "vpc_flow"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            lines = text.strip().split("\n")
            if not lines:
                return

            # First line is header
            header = lines[0].strip().split()
            # Map header fields to our names
            field_names = [f.replace("-", "_") for f in header]

            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) != len(field_names):
                    continue
                record = dict(zip(field_names, parts))

                # Skip NODATA entries
                if record.get("log_status") == "NODATA":
                    continue

                # Map protocol number to name
                record["protocol_name"] = _PROTOCOL_MAP.get(record.get("protocol", ""), record.get("protocol", ""))

                yield record

        except Exception as exc:
            logger.debug(f"VPC Flow parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "resource.account_id": "account_id",
            "network.src_ip": "srcaddr",
            "network.dst_ip": "dstaddr",
            "network.src_port": "srcport",
            "network.dst_port": "dstport",
            "network.protocol": "protocol_name",
            "network.packets": "packets",
            "network.bytes_in": "bytes",
            "network.flow_action": "action",
        }

    def get_event_category(self) -> str:
        return EventCategory.NETWORK_ACTIVITY
