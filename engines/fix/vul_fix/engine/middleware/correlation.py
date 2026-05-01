"""
Correlation ID Middleware.

Reads X-Request-ID from the incoming request (set by API gateway or caller)
or generates a new UUID if absent. Stores it in the async context variable so
every log line emitted during that request automatically includes it.
Echoes the ID back in the X-Request-ID response header.

This means:
  - A caller can trace a request end-to-end by setting X-Request-ID.
  - An API gateway can inject the header and correlate across services.
  - Log aggregators (ELK, CloudWatch Insights) can filter by request_id.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from logging_config import set_request_id


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Honour caller-supplied ID (from API gateway / upstream service);
        # generate a fresh UUID if none provided.
        request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid.uuid4())
        set_request_id(request_id)

        response = await call_next(request)
        # Echo back so the caller can log it on their side too
        response.headers["X-Request-ID"] = request_id
        return response
