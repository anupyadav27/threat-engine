"""
Internal async HTTP client for CWPP engine.
Calls sibling engine APIs with timeout and graceful error handling.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("cwpp.http_client")

DEFAULT_TIMEOUT = 25.0  # seconds

CIEM_ENGINE_URL = os.getenv("CIEM_ENGINE_URL", "http://engine-ciem/api/v1")


async def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    auth_header: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """GET a JSON endpoint; returns None on any error (engine unavailable, timeout, etc.)."""
    headers = {"X-Auth-Context": auth_header} if auth_header else {}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("Timeout calling %s", url)
    except httpx.HTTPStatusError as e:
        logger.warning("HTTP %s from %s", e.response.status_code, url)
    except Exception as e:
        logger.warning("Error calling %s: %s", url, e)
    return None
