"""
ALB Access Log parser — space-delimited text with quoted strings.

Format: type timestamp elb client:port target:port request_processing_time
        target_processing_time response_processing_time elb_status_code
        target_status_code received_bytes sent_bytes "request" "user_agent"
        ssl_cipher ssl_protocol target_group_arn "trace_id" "domain_name"
        "chosen_cert_arn" matched_rule_priority request_creation_time
        "actions_executed" "redirect_url" "error_reason" "target:port_list"
        "target_status_code_list" "classification" "classification_reason"
"""

import logging
import re
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

# Regex to split ALB log line respecting quoted strings
_FIELD_RE = re.compile(r'"([^"]*)"|\S+')


class ALBParser(BaseParser):
    format_name = "alb"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for line in text.strip().split("\n"):
                if not line.strip():
                    continue
                fields = [m.group(1) or m.group(0) for m in _FIELD_RE.finditer(line)]
                if len(fields) < 12:
                    continue

                # Parse request: "METHOD URL PROTOCOL"
                request = fields[11] if len(fields) > 11 else ""
                req_parts = request.split(" ", 2)
                method = req_parts[0] if req_parts else ""
                url = req_parts[1] if len(req_parts) > 1 else ""

                # Parse client IP:port
                client = fields[3] if len(fields) > 3 else ""
                client_ip = client.split(":")[0] if ":" in client else client

                record = {
                    "type": fields[0],
                    "timestamp": fields[1],
                    "elb": fields[2],
                    "client_ip": client_ip,
                    "client_port": client.split(":")[-1] if ":" in client else "",
                    "target": fields[4] if len(fields) > 4 else "",
                    "elb_status_code": fields[8] if len(fields) > 8 else "",
                    "target_status_code": fields[9] if len(fields) > 9 else "",
                    "received_bytes": fields[10] if len(fields) > 10 else "0",
                    "sent_bytes": fields[11] if len(fields) > 11 else "0",
                    "method": method,
                    "url": url,
                    "user_agent": fields[12] if len(fields) > 12 else "",
                    "response_time_ms": fields[5] if len(fields) > 5 else "0",
                }
                yield record

        except Exception as exc:
            logger.debug(f"ALB parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.ip_address": "client_ip",
            "actor.user_agent": "user_agent",
            "http.method": "method",
            "http.url": "url",
            "http.status_code": "elb_status_code",
            "network.bytes_in": "received_bytes",
            "network.bytes_out": "sent_bytes",
        }

    def get_event_category(self) -> str:
        return EventCategory.HTTP_ACTIVITY
