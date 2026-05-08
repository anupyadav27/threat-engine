"""
WAF Log parser — JSON lines (one event per line).

WAF logs are delivered to S3 as JSON lines:
  {"timestamp":1234567890000,"formatVersion":1,"webaclId":"...","action":"ALLOW",...}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class WAFParser(BaseParser):
    format_name = "waf"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for line in text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    # Add derived fields
                    record["_action"] = record.get("action", "").upper()
                    http_request = record.get("httpRequest", {})
                    record["_client_ip"] = http_request.get("clientIp", "")
                    record["_method"] = http_request.get("httpMethod", "")
                    record["_uri"] = http_request.get("uri", "")
                    record["_host"] = ""
                    for h in http_request.get("headers", []):
                        if h.get("name", "").lower() == "host":
                            record["_host"] = h.get("value", "")
                            break
                    yield record
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            logger.debug(f"WAF parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.ip_address": "_client_ip",
            "http.method": "_method",
            "http.url": "_uri",
            "http.host": "_host",
            "operation": "_action",
            "resource.uid": "webaclId",
        }

    def get_event_category(self) -> str:
        return EventCategory.SECURITY_FINDING
