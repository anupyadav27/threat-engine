"""
Platform Admin Engine — Engine health grid router.

GET /api/v1/padmin/engines/health

Polls all known engine pods via:
  1. Kubernetes API — pod count, ready count, restart count.
  2. Each engine's /api/v1/health/live endpoint — HTTP status + latency.

All checks run concurrently via asyncio.gather with a 3-second timeout
per HTTP health check. Requires platform:admin permission.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends

try:
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

from k8s_client import ENGINE_NAMES, NAMESPACE, get_k8s_client
from _schemas import PlatformAdminLenientResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["engine-health"])

# Internal K8s service health URL per engine name.
_HEALTH_URL_MAP: Dict[str, str] = {
    "engine-discoveries":      "http://engine-discoveries:8001/api/v1/health/live",
    "engine-check-aws":        "http://engine-check-aws:8002/api/v1/health/live",
    "engine-inventory":        "http://engine-inventory:8022/api/v1/health/live",
    "engine-threat":           "http://engine-threat:8020/api/v1/health/live",
    "engine-compliance":       "http://engine-compliance:8000/api/v1/health/live",
    "engine-iam":              "http://engine-iam:80/api/v1/health/live",
    "engine-datasec":          "http://engine-datasec:8003/api/v1/health/live",
    "engine-secops":           "http://engine-secops:8005/api/v1/health/live",
    "engine-network-security": "http://engine-network-security:8004/api/v1/health/live",
    "engine-ciem":             "http://engine-ciem:80/api/v1/health/live",
    "engine-risk":             "http://engine-risk:80/api/v1/health/live",
    "engine-vulnerability":    "http://engine-vulnerability:80/api/v1/health/live",
    "engine-ai-security":      "http://engine-ai-security:80/api/v1/health/live",
    "engine-encryption":       "http://engine-encryption:80/api/v1/health/live",
    "engine-dbsec":            "http://engine-dbsec:80/api/v1/health/live",
    "engine-container-sec":    "http://engine-container-sec:80/api/v1/health/live",
    "engine-billing":          "http://engine-billing:8040/api/v1/health/live",
    "engine-platform-admin":   "http://engine-platform-admin:8041/api/v1/health/live",
}


def _get_health_url(engine_name: str) -> Optional[str]:
    """Return the internal K8s service health URL for a given engine.

    Args:
        engine_name: The Deployment/Service name in the cluster.

    Returns:
        Full health URL string, or None if the engine is not in the map.
    """
    return _HEALTH_URL_MAP.get(engine_name)


async def _check_engine(engine_name: str, core_v1: Any) -> Dict[str, Any]:
    """Query K8s pod status and call the engine's /health/live endpoint.

    Args:
        engine_name: The Deployment/Service label app= value.
        core_v1: kubernetes.client.CoreV1Api instance.

    Returns:
        Dict with engine_name, pod_status, pod_count, ready_pods,
        restart_count, health_check_status, health_check_latency_ms.
    """
    result: Dict[str, Any] = {
        "engine_name": engine_name,
        "pod_status": "unknown",
        "pod_count": 0,
        "ready_pods": 0,
        "restart_count": 0,
        "health_check_status": "unknown",
        "health_check_latency_ms": -1,
    }

    # 1. Kubernetes pod status
    try:
        pods = core_v1.list_namespaced_pod(
            namespace=NAMESPACE,
            label_selector=f"app={engine_name}",
        )
        result["pod_count"] = len(pods.items)
        if pods.items:
            pod = pods.items[0]
            result["pod_status"] = (pod.status.phase or "unknown").lower()
            container_statuses = pod.status.container_statuses or []
            result["ready_pods"] = sum(1 for cs in container_statuses if cs.ready)
            result["restart_count"] = sum(cs.restart_count for cs in container_statuses)
    except Exception as exc:
        logger.warning("K8s pod query failed for %s: %s", engine_name, exc)
        result["pod_status"] = "error"

    # 2. HTTP health check
    health_url = _get_health_url(engine_name)
    if health_url:
        try:
            t0 = time.monotonic()
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(health_url)
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            result["health_check_latency_ms"] = elapsed_ms
            result["health_check_status"] = "ok" if resp.status_code == 200 else "degraded"
        except httpx.TimeoutException:
            result["health_check_status"] = "timeout"
        except Exception:
            result["health_check_status"] = "unreachable"

    return result


@router.get("/engines/health", response_model=PlatformAdminLenientResponse, response_model_exclude_none=False)
async def get_engines_health(
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return health status for all known engines.

    Polls Kubernetes pod status and each engine's /api/v1/health/live
    endpoint concurrently. Results include a summary counts object.

    Requires platform:admin permission.

    Args:
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'engines' list and 'summary' counts dict.
    """
    try:
        core_v1, _apps_v1 = get_k8s_client()
    except RuntimeError as exc:
        logger.error("Cannot load K8s client: %s", exc)
        core_v1 = None

    tasks = [_check_engine(name, core_v1) for name in ENGINE_NAMES]
    raw_results: List[Any] = await asyncio.gather(*tasks, return_exceptions=True)

    engines: List[Dict[str, Any]] = []
    for name, result in zip(ENGINE_NAMES, raw_results):
        if isinstance(result, Exception):
            engines.append(
                {
                    "engine_name": name,
                    "pod_status": "unknown",
                    "pod_count": 0,
                    "ready_pods": 0,
                    "restart_count": 0,
                    "health_check_status": "error",
                    "health_check_latency_ms": -1,
                    "error": str(result),
                }
            )
        else:
            engines.append(result)

    healthy = sum(1 for e in engines if e.get("health_check_status") == "ok")
    degraded = sum(
        1
        for e in engines
        if e.get("pod_status") == "running" and e.get("health_check_status") != "ok"
    )
    down = sum(
        1 for e in engines if e.get("pod_status") not in ("running", "unknown", "error")
    )

    return {
        "engines": engines,
        "summary": {
            "total_engines": len(engines),
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
        },
    }
