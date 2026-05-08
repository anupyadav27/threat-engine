"""
Internal async HTTP client for CNAPP engine.
Calls sibling engine APIs with timeout and graceful error handling.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("cnapp.http_client")

DEFAULT_TIMEOUT = 20.0  # seconds — engines may be slow on first call


async def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """GET a JSON endpoint; returns None on any error (engine unavailable, timeout, etc.)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers or {})
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("Timeout calling %s", url)
    except httpx.HTTPStatusError as e:
        logger.warning("HTTP %s from %s", e.response.status_code, url)
    except Exception as e:
        logger.warning("Error calling %s: %s", url, e)
    return None


async def post(
    url: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """POST JSON to an endpoint; returns None on any error."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=body or {}, headers=headers or {})
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("Timeout posting to %s", url)
    except httpx.HTTPStatusError as e:
        logger.warning("HTTP %s from %s", e.response.status_code, url)
    except Exception as e:
        logger.warning("Error posting to %s: %s", url, e)
    return None
