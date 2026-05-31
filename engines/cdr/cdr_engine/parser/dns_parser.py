"""
Route53 DNS Query Log parser — JSON from CloudWatch Logs.

Each record:
{
  "version": "1.100000",
  "account_id": "123456789012",
  "region": "us-east-1",
  "vpc_id": "vpc-abc123",
  "query_timestamp": "2026-03-25T10:30:00Z",
  "query_name": "example.com.",
  "query_type": "A",
  "query_class": "IN",
  "rcode": "NOERROR",
  "answers": [...],
  "srcaddr": "10.0.0.5",
  "srcport": "12345",
  "transport": "UDP",
  "firewall_rule_action": "ALLOW"
}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class DNSParser(BaseParser):
    format_name = "dns"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for line in text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    record["_query"] = record.get("query_name", "").rstrip(".")
                    record["_action"] = record.get("firewall_rule_action", record.get("rcode", ""))
                    yield record
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            logger.debug(f"DNS parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.ip_address": "srcaddr",
            "resource.uid": "vpc_id",
            "resource.account_id": "account_id",
            "resource.region": "region",
            "operation": "_query",
            "network.src_port": "srcport",
            "network.protocol": "transport",
        }

    def get_event_category(self) -> str:
        return EventCategory.DNS_ACTIVITY
