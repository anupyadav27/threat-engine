"""
S3 Server Access Log parser — space-delimited with quoted strings and brackets.

Format: bucket_owner bucket [timestamp] remote_ip requester request_id operation
        key request_uri http_status error_code bytes_sent object_size total_time
        turn_around_time referrer user_agent version_id host_id ...

Example:
  79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
  mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
  3E57427F3EXAMPLE REST.GET.OBJECT s3-dg.pdf "GET /mybucket/s3-dg.pdf HTTP/1.1"
  200 - 3358 3358 33 - "-" "Amazon CloudFront" -
"""

import logging
import re
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

_FIELD_RE = re.compile(r'\[([^\]]*)\]|"([^"]*)"|(\S+)')


class S3AccessParser(BaseParser):
    format_name = "s3_access"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for line in text.strip().split("\n"):
                if not line.strip():
                    continue
                fields = [m.group(1) or m.group(2) or m.group(3) for m in _FIELD_RE.finditer(line)]
                if len(fields) < 11:
                    continue

                record = {
                    "bucket_owner": fields[0],
                    "bucket": fields[1],
                    "timestamp": fields[2],
                    "remote_ip": fields[3],
                    "requester": fields[4],
                    "request_id": fields[5],
                    "operation": fields[6],
                    "key": fields[7],
                    "request_uri": fields[8] if len(fields) > 8 else "",
                    "http_status": fields[9] if len(fields) > 9 else "",
                    "error_code": fields[10] if len(fields) > 10 else "",
                    "bytes_sent": fields[11] if len(fields) > 11 else "0",
                    "object_size": fields[12] if len(fields) > 12 else "0",
                    "user_agent": fields[16] if len(fields) > 16 else "",
                }
                # Build resource_uid
                record["_resource_uid"] = f"arn:aws:s3:::{record['bucket']}"
                if record["key"] and record["key"] != "-":
                    record["_resource_uid"] += f"/{record['key']}"

                yield record

        except Exception as exc:
            logger.debug(f"S3 access parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.ip_address": "remote_ip",
            "actor.principal": "requester",
            "actor.user_agent": "user_agent",
            "operation": "operation",
            "resource.uid": "_resource_uid",
            "http.status_code": "http_status",
            "network.bytes_out": "bytes_sent",
            "error_code": "error_code",
        }

    def get_event_category(self) -> str:
        return EventCategory.DATA_ACCESS
