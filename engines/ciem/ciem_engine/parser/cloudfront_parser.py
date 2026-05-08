"""
CloudFront Access Log parser — tab-separated.

Format: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem
        sc-status cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie)
        x-edge-result-type x-edge-request-id x-host-header cs-protocol
        cs-bytes time-taken x-forwarded-for ssl-protocol ssl-cipher
        x-edge-response-result-type ...

First 2 lines are comments (#Version, #Fields).
"""

import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class CloudFrontParser(BaseParser):
    format_name = "cloudfront"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            lines = text.strip().split("\n")

            # Find field names from #Fields line
            field_names = None
            for line in lines:
                if line.startswith("#Fields:"):
                    field_names = line.replace("#Fields:", "").strip().split()
                    break

            if not field_names:
                # Default CloudFront field order
                field_names = [
                    "date", "time", "x-edge-location", "sc-bytes", "c-ip",
                    "cs-method", "cs-host", "cs-uri-stem", "sc-status",
                    "cs-referer", "cs-user-agent", "cs-uri-query",
                ]

            for line in lines:
                if line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < len(field_names):
                    continue
                record = dict(zip(field_names, parts))
                # Combine date + time
                record["_timestamp"] = f"{record.get('date', '')}T{record.get('time', '')}Z"
                record["_url"] = f"{record.get('cs-uri-stem', '')}"
                if record.get("cs-uri-query", "-") != "-":
                    record["_url"] += f"?{record['cs-uri-query']}"
                yield record

        except Exception as exc:
            logger.debug(f"CloudFront parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.ip_address": "c-ip",
            "actor.user_agent": "cs-user-agent",
            "http.method": "cs-method",
            "http.url": "_url",
            "http.status_code": "sc-status",
            "http.host": "cs-host",
            "network.bytes_out": "sc-bytes",
        }

    def get_event_category(self) -> str:
        return EventCategory.HTTP_ACTIVITY
