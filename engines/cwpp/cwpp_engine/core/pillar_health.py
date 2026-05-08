"""
CWPP pillar health checker and score fetcher.

All health checks and score fetches use a 5-second timeout enforced via
asyncio.wait_for() so a slow or unresponsive engine never blocks the
CWPP aggregate response.

Unavailable pillar → score=None, reason="engine_unavailable".

Internal ClusterIP URLs only — no external ELB exposure (AC-S2).
CWPP pillars: workload_security (container_sec) + ai_security.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger("cwpp.core.pillar_health")

HEALTH_TIMEOUT = 5.0  # seconds — per pillar (AC-S5)
SCORE_TIMEOUT = 5.0   # seconds — per pillar score fetch

# Internal ClusterIP service URLs only (AC-S2)
CWPP_PILLAR_HEALTH_ENDPOINTS: Dict[str, str] = {
    "container_sec": "http://engine-container-sec/api/v1/health/ready",
    "ai_security":   "http://engine-ai-security/api/v1/health/ready",
}

# Score fetch endpoints per source key
# All queries include tenant_id (AC-S7)
CWPP_PILLAR_SCORE_ENDPOINTS: Dict[str, str] = {
    "container_sec": "http://engine-container-sec/api/v1/container-security/ui-data",
    "ai_security":   "http://engine-ai-security/api/v1/ai-security/ui-data",
}


async def _check_single_health(name: str, url: str) -> Tuple[str, bool]:
    """Check a single pillar's health endpoint with HEALTH_TIMEOUT.

    Args:
        name: Pillar source key.
        url: Internal ClusterIP health URL.

    Returns:
        Tuple of (name, is_available).
    """
    try:
        async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT) as client:
            resp = await asyncio.wait_for(
                asyncio.shield(client.get(url)),
                timeout=HEALTH_TIMEOUT,
            )
            return name, resp.status_code == 200
    except (asyncio.TimeoutError, httpx.TimeoutException):
        logger.warning("Health check timeout: %s (%s)", name, url)
        return name, False
    except Exception as exc:
        logger.warning("Health check failed: %s (%s): %s", name, url, exc)
        return name, False


async def check_pillar_health(
    endpoints: Dict[str, str],
) -> Dict[str, bool]:
    """Check health for all CWPP pillars concurrently with 5s per-pillar timeout.

    Args:
        endpoints: Dict mapping source key → health URL.

    Returns:
        Dict mapping source key → True (available) / False (unavailable).
    """
    tasks = [_check_single_health(name, url) for name, url in endpoints.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    health: Dict[str, bool] = {}
    for result in results:
        if isinstance(result, Exception):
            logger.warning("Unexpected error in health check gather: %s", result)
            continue
        name, available = result
        health[name] = available
    return health


async def _fetch_single_score(
    name: str,
    url: str,
    scan_run_id: str,
    tenant_id: str,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Fetch score data for a single pillar with SCORE_TIMEOUT.

    Args:
        name: Pillar source key.
        url: Score endpoint URL.
        scan_run_id: Scan run identifier.
        tenant_id: Tenant identifier — included in ALL queries (AC-S7).

    Returns:
        Tuple of (name, response_dict_or_None).
    """
    # tenant_id included in ALL queries (AC-S7)
    params: Dict[str, str] = {
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
    }
    # container-security engine uses scan_id alias
    if name == "container_sec":
        params["scan_id"] = scan_run_id

    try:
        async with httpx.AsyncClient(timeout=SCORE_TIMEOUT) as client:
            resp = await asyncio.wait_for(
                asyncio.shield(client.get(url, params=params)),
                timeout=SCORE_TIMEOUT,
            )
            resp.raise_for_status()
            return name, resp.json()
    except (asyncio.TimeoutError, httpx.TimeoutException):
        logger.warning("Score fetch timeout: %s (%s)", name, url)
        return name, None
    except httpx.HTTPStatusError as exc:
        logger.warning("Score fetch HTTP %s: %s (%s)", exc.response.status_code, name, url)
        return name, None
    except Exception as exc:
        logger.warning("Score fetch error: %s (%s): %s", name, url, exc)
        return name, None


async def fetch_all_pillar_scores(
    health: Dict[str, bool],
    scan_run_id: str,
    tenant_id: str,
) -> Dict[str, Optional[Dict[str, Any]]]:
    """Fetch scores for all available CWPP pillars concurrently.

    Pillars marked unavailable in the health dict are skipped —
    their entry in the result is None without an HTTP call.

    Args:
        health: Dict mapping source key → bool from check_pillar_health().
        scan_run_id: Scan run identifier.
        tenant_id: Tenant identifier — scoped to all queries.

    Returns:
        Dict mapping source key → response dict (or None if unavailable/error).
    """
    tasks = []
    skipped: Dict[str, None] = {}

    for name, url in CWPP_PILLAR_SCORE_ENDPOINTS.items():
        if not health.get(name, False):
            skipped[name] = None
        else:
            tasks.append(_fetch_single_score(name, url, scan_run_id, tenant_id))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    scores: Dict[str, Optional[Dict[str, Any]]] = dict(skipped)
    for result in gathered:
        if isinstance(result, Exception):
            logger.warning("Unexpected error in score gather: %s", result)
            continue
        name, data = result
        scores[name] = data

    return scores


def extract_container_sec_score(data: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract workload posture score from container-security engine response.

    Args:
        data: Raw JSON response from container-security engine, or None.

    Returns:
        Integer score 0-100, or None.
    """
    if data is None:
        return None

    summary = data.get("summary") or {}
    sub_scores = []
    for key in (
        "cluster_security_score",
        "workload_security_score",
        "rbac_access_score",
        "runtime_audit_score",
    ):
        v = summary.get(key)
        if v is not None:
            sub_scores.append(float(v))
    if sub_scores:
        return round(sum(sub_scores) / len(sub_scores))
    overall = summary.get("posture_score") or data.get("posture_score")
    return round(float(overall)) if overall is not None else None


def extract_ai_security_score(data: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract posture score from ai-security engine response.

    Args:
        data: Raw JSON response from ai-security engine, or None.

    Returns:
        Integer score 0-100, or None.
    """
    if data is None:
        return None
    score = (
        data.get("posture_score")
        or data.get("overall_score")
        or data.get("ai_posture_score")
    )
    return round(float(score)) if score is not None else None


def extract_findings_count(data: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract total findings count from a pillar response.

    Args:
        data: Raw JSON response dict, or None.

    Returns:
        Integer count, or None if unavailable.
    """
    if data is None:
        return None

    summary = data.get("summary") or {}
    for key in ("total_findings", "total", "finding_count"):
        val = data.get(key) or summary.get(key)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
    return None
