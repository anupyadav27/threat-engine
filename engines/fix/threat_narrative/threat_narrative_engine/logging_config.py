"""
Structured JSON logging for Threat Narrative Engine.

Every log line is a single JSON object — parseable by CloudWatch, ELK, Datadog.
Fields:
  ts          — ISO-8601 timestamp
  level       — DEBUG / INFO / WARNING / ERROR / CRITICAL
  logger      — logger name
  request_id  — correlation ID from X-Request-ID header (or auto-generated UUID)
  msg         — log message

Usage:
  from threat_narrative_engine.logging_config import configure_logging
  configure_logging("threat_narrative")
"""

import json
import logging
import sys
from contextvars import ContextVar

# ── Correlation ID — per-request context variable ─────────────────────────────
_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def get_request_id() -> str:
    """Return the current request correlation ID."""
    return _request_id_var.get()


def set_request_id(request_id: str) -> None:
    """Set the current request correlation ID."""
    _request_id_var.set(request_id)


class _JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict = {
            "ts":         self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":      record.levelname,
            "logger":     record.name,
            "request_id": _request_id_var.get(),
            "msg":        record.getMessage(),
        }
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        for key, val in record.__dict__.items():
            if key not in (
                "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno",
                "funcName", "created", "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process", "name", "message",
            ):
                if not key.startswith("_"):
                    data[key] = val
        return json.dumps(data, default=str)


def configure_logging(service_name: str, level: int = logging.INFO) -> None:
    """Replace root logger handlers with a single JSON stream handler.

    Call once at the top of main.py before any other imports.

    Args:
        service_name: Service identifier for the initial log message.
        level: Logging level (default: INFO).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    logging.getLogger(service_name).info(
        "JSON structured logging enabled",
        extra={"service": service_name},
    )
