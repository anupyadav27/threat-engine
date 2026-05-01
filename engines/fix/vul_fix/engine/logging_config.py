"""
Structured JSON logging for VulFix Engine.

Every log line is a single JSON object — parseable by CloudWatch, ELK, Datadog.
Fields:
  ts          — ISO-8601 timestamp
  level       — DEBUG / INFO / WARNING / ERROR / CRITICAL
  logger      — logger name (e.g. "vul_fix", "core.ai_fixer")
  request_id  — correlation ID from X-Request-ID header (or auto-generated UUID)
  msg         — log message

Usage:
  from logging_config import configure_logging, get_request_id, set_request_id
  configure_logging("vul_fix")
"""

import json
import logging
import sys
from contextvars import ContextVar

# ── Correlation ID — per-request context variable ─────────────────────────────
# Set by CorrelationIDMiddleware at the start of each HTTP request.
# Automatically propagates through all async coroutines in the same request context.
_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def get_request_id() -> str:
    return _request_id_var.get()


def set_request_id(request_id: str) -> None:
    _request_id_var.set(request_id)


class _JSONFormatter(logging.Formatter):
    """
    Formats each LogRecord as a single JSON line.
    Includes the request correlation ID from the async context variable.
    """

    def format(self, record: logging.LogRecord) -> str:
        data: dict = {
            "ts":         self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":      record.levelname,
            "logger":     record.name,
            "request_id": _request_id_var.get(),
            "msg":        record.getMessage(),
        }
        # Attach exception traceback when present
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        # Attach any extra fields passed via logger.info("msg", extra={...})
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
    """
    Replace the root logger's handlers with a single JSON stream handler.
    Call once at module load time in api_server.py before any other imports
    that touch logging.

    Args:
        service_name: Used as the root logger name in startup messages.
        level:        Log level (default INFO).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Suppress noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("git").setLevel(logging.WARNING)

    logging.getLogger(service_name).info(
        f"JSON structured logging enabled",
        extra={"service": service_name},
    )
