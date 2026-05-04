"""
CNAPP pillar health checker and score fetcher.

All health checks and score fetches use a 5-second timeout enforced via
asyncio.wait_for() so a slow or unresponsive engine never blocks the
CNAPP aggregate response.

Unavailable pillar → score=None, reason="engine_unavailable".
Available pillar with no findings → score may be None with reason="no_data".

Internal ClusterIP URLs only — no external ELB exposure (AC-S2).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger("cnapp.core.pillar_health")

HEALTH_TIMEOUT = 5.0  # seconds — per pillar (AC-S5)
SCORE_TIMEOUT = 5.0   # seconds — per pillar score fetch

# Internal ClusterIP service URLs only (AC-S2)
CNAPP_PILLAR_HEALTH_ENDPOINTS: Dict[str, str] = {
    "check":         "http://engine-check-aws/api/v1/health/ready",
    "network":       "http://engine-network-security/api/v1/health/ready",
    "datasec":       "http://engine-datasec/api/v1/health/ready",
    "iam":           "http://engine-iam/api/v1/health/ready",
    "container_sec": "http://engine-container-sec/api/v1/health/ready",
    "risk":          "http://engine-risk/api/v1/health/ready",
    "ai_security":   "http://engine-ai-security/api/v1/health/ready",
    "dbsec":         "http://engine-dbsec/api/v1/health/ready",
}

# Score fetch endpoints per source engine key
# All queries include tenant_id (AC-S1)
CNAPP_PILLAR_SCORE_ENDPOINTS: Dict[str, str] = {
    "check":         "http://engine-check-aws/api/v1/check/findings/summary",
    "network":       "http://engine-network-security/api/v1/network-security/ui-data",
    "datasec":       "http://engine-datasec/api/v1/data-security/ui-data",
    "iam":           "http://engine-iam/api/v1/iam-security/ui-data",
    "container_sec": "http://engine-container-sec/api/v1/container-security/ui-data",
    "risk":          "http://engine-risk/api/v1/risk/summary",
    "ai_security":   "http://engine-ai-security/api/v1/ai-security/ui-data",
    "dbsec":         "http://engine-dbsec/api/v1/dbsec/ui-data",
}


async def _check_single_health(name: str, url: str) -> Tuple[str, bool]:
    """Check a single pillar's health endpoint with HEALTH_TIMEOUT.

    Args:
        name: Pillar source key (e.g. "check", "datasec").
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
    except Exception as e:
        logger.warning("Health check failed: %s (%s): %s", name, url, e)
        return name, False


async def check_pillar_health(
    endpoints: Dict[str, str],
) -> Dict[str, bool]:
    """Check health for all pillars concurrently with 5s per-pillar timeout.

    Args:
        endpoints: Dict mapping pillar source key → health URL.

    Returns:
        Dict mapping pillar source key → True (available) / False (unavailable).
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
        tenant_id: Tenant identifier — included in ALL queries (AC-S1).

    Returns:
        Tuple of (name, response_dict_or_None).
    """
    # tenant_id included in params for every pillar (AC-S1)
    params: Dict[str, str] = {
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
    }
    # network engine uses scan_id alias
    if name == "network":
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
    """Fetch scores for all available pillars concurrently.

    Pillars marked unavailable in the health dict are skipped —
    their entry in the result is None without an HTTP call.

    Args:
        health: Dict mapping source key → bool from check_pillar_health().
        scan_run_id: Scan run identifier.
        tenant_id: Tenant identifier scoped to all queries.

    Returns:
        Dict mapping source key → response dict (or None if unavailable/error).
    """
    tasks = []
    skipped: Dict[str, None] = {}

    for name, url in CNAPP_PILLAR_SCORE_ENDPOINTS.items():
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


def extract_score_from_response(name: str, data: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract an integer 0-100 posture score from a pillar's response payload.

    Args:
        name: Pillar source key (used to choose extraction path).
        data: Raw JSON response dict, or None.

    Returns:
        Integer score 0-100, or None if unavailable/no data.
    """
    if data is None:
        return None

    # Check engine: pass_rate from status_counts
    if name == "check":
        total = data.get("total") or data.get("total_checks") or 0
        if total:
            sc = data.get("status_counts") or {}
            passed = (
                sc.get("PASS") or sc.get("pass")
                or data.get("passed") or data.get("pass_count") or 0
            )
            return round(int(passed) / int(total) * 100)
        rate = data.get("pass_rate") or data.get("pass_rate_pct")
        if rate is not None:
            return round(float(rate))
        return None

    # Network engine: pass_rate in summary
    if name == "network":
        summary = data.get("summary") or {}
        score = (
            summary.get("pass_rate")
            or summary.get("posture_score")
            or data.get("posture_score")
            or data.get("network_posture_score")
            or data.get("overall_score")
        )
        return round(float(score)) if score is not None else None

    # Datasec: data_risk_score → invert
    if name == "datasec":
        summary = data.get("summary") or {}
        risk = summary.get("data_risk_score")
        if risk is not None:
            return round(max(0.0, 100.0 - float(risk)))
        score = data.get("posture_score") or data.get("overall_score")
        return round(float(score)) if score is not None else None

    # IAM engine
    if name == "iam":
        summary = data.get("summary") or {}
        risk = summary.get("risk_score")
        if risk is not None:
            return round(max(0.0, 100.0 - float(risk)))
        score = data.get("posture_score") or data.get("pass_rate") or data.get("overall_score")
        return round(float(score)) if score is not None else None

    # Container-sec: average sub-domain scores
    if name == "container_sec":
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

    # Risk engine
    if name == "risk":
        score = (
            data.get("posture_score")
            or data.get("overall_score")
            or data.get("risk_posture_score")
        )
        if score is not None:
            return round(float(score))
        # If engine returns risk score (0-100 risk → invert for posture)
        risk = data.get("risk_score") or (data.get("summary") or {}).get("risk_score")
        if risk is not None:
            return round(max(0.0, 100.0 - float(risk)))
        return None

    # AI-security engine
    if name == "ai_security":
        score = (
            data.get("posture_score")
            or data.get("overall_score")
            or data.get("ai_posture_score")
        )
        return round(float(score)) if score is not None else None

    # DBSec engine
    if name == "dbsec":
        score = (
            data.get("posture_score")
            or data.get("overall_score")
            or data.get("dbsec_posture_score")
        )
        return round(float(score)) if score is not None else None

    # Generic fallback
    score = data.get("posture_score") or data.get("overall_score")
    return round(float(score)) if score is not None else None


def extract_findings_count(name: str, data: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract total findings count from a pillar's response payload.

    Args:
        name: Pillar source key.
        data: Raw JSON response dict, or None.

    Returns:
        Integer count, or None if unavailable.
    """
    if data is None:
        return None

    summary = data.get("summary") or {}

    # Try common keys
    for key in (
        "total_findings",
        "total",
        "total_checks",
        "total_threats",
        "finding_count",
    ):
        val = data.get(key) or summary.get(key)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass

    return None
