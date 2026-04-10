"""
Lambda Log parser — parses Lambda function logs from CloudWatch.

Lambda logs are unstructured text with START/END/REPORT markers.
Security-relevant events: errors, timeouts, permission denials, cold starts.
"""

import json
import logging
import re
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

# Lambda log patterns
_REPORT_PATTERN = re.compile(
    r"REPORT RequestId: (?P<request_id>\S+)\s+"
    r"Duration: (?P<duration_ms>[\d.]+) ms\s+"
    r"Billed Duration: (?P<billed_ms>\d+) ms\s+"
    r"Memory Size: (?P<memory_mb>\d+) MB\s+"
    r"Max Memory Used: (?P<max_memory_mb>\d+) MB"
)


class LambdaParser(BaseParser):
    format_name = "lambda"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse CloudWatch batch of Lambda log events."""
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            batch = json.loads(text)

            for entry in batch:
                msg = entry.get("message", "").strip()
                ts = entry.get("timestamp", 0)
                if not msg:
                    continue

                # Skip START/END markers (low value)
                if msg.startswith("START RequestId:") or msg.startswith("END RequestId:"):
                    continue

                record = {
                    "timestamp": ts,
                    "message": msg,
                    "log_stream": entry.get("logStreamName", ""),
                }

                # Parse REPORT lines
                match = _REPORT_PATTERN.search(msg)
                if match:
                    record.update({
                        "event_type": "invocation_report",
                        "request_id": match.group("request_id"),
                        "duration_ms": float(match.group("duration_ms")),
                        "billed_ms": int(match.group("billed_ms")),
                        "memory_mb": int(match.group("memory_mb")),
                        "max_memory_mb": int(match.group("max_memory_mb")),
                    })
                    # Flag high memory usage
                    if record["max_memory_mb"] > record["memory_mb"] * 0.9:
                        record["risk_flag"] = "near_memory_limit"
                    yield record
                    continue

                # Try JSON structured logs
                try:
                    structured = json.loads(msg)
                    if isinstance(structured, dict):
                        record.update(structured)
                        record["event_type"] = "structured"
                        # Look for error indicators
                        level = str(structured.get("level", structured.get("severity", ""))).lower()
                        if level in ("error", "critical", "fatal"):
                            record["event_type"] = "error"
                        yield record
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass

                # Plain text — only yield errors and security events
                msg_lower = msg.lower()
                if any(kw in msg_lower for kw in (
                    "error", "exception", "denied", "forbidden",
                    "timeout", "accessdenied", "unauthorized",
                )):
                    record["event_type"] = "error"
                    yield record

        except Exception as exc:
            logger.debug(f"Lambda parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_time": "timestamp",
            "operation": "event_type",
        }

    def get_event_category(self) -> str:
        return EventCategory.APPLICATION_ACTIVITY
