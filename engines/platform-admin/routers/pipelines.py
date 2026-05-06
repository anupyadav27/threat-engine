"""
Platform Admin Engine — Argo pipeline runs router.

GET /api/v1/padmin/pipeline/runs

Queries the Argo Workflows REST API for recent workflow runs in the
threat-engine-engines namespace. Requires platform:admin permission.

Argo REST API docs: https://argoproj.github.io/argo-workflows/rest-api/
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from argo_client import ARGO_NAMESPACE, ARGO_SERVER_URL, get_argo_headers
from _schemas import PlatformAdminLenientResponse

try:
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["pipelines"])

_ARGO_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_duration(started: Optional[str], finished: Optional[str]) -> Optional[int]:
    """Compute workflow duration in seconds from ISO timestamps.

    Args:
        started: Argo startedAt string (e.g. '2026-05-01T10:00:00Z').
        finished: Argo finishedAt string.

    Returns:
        Duration in whole seconds, or None if either timestamp is missing
        or cannot be parsed.
    """
    if not started or not finished:
        return None
    try:
        start_dt = datetime.strptime(started, _ARGO_TIME_FMT)
        end_dt = datetime.strptime(finished, _ARGO_TIME_FMT)
        return int((end_dt - start_dt).total_seconds())
    except ValueError:
        return None


def _extract_failed_steps(nodes: Optional[Dict[str, Any]]) -> List[str]:
    """Return display names of workflow nodes whose phase is 'Failed'.

    Args:
        nodes: Argo workflow status.nodes dict (node_id → node object).

    Returns:
        List of displayName strings for failed nodes.
    """
    if not nodes:
        return []
    return [
        node.get("displayName", node_id)
        for node_id, node in nodes.items()
        if node.get("phase") == "Failed"
    ]


@router.get("/pipeline/runs", response_model=PlatformAdminLenientResponse, response_model_exclude_none=False)
async def list_pipeline_runs(
    org_id: Optional[str] = Query(None, description="Filter by org_id annotation"),
    limit: int = Query(50, ge=1, le=200, description="Maximum workflows to return"),
    status: Optional[str] = Query(
        None, description="Filter by phase: Succeeded, Failed, Running, Error"
    ),
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return recent Argo Workflow runs from the threat-engine-engines namespace.

    Queries the Argo Workflows REST API and normalises each workflow entry
    into a summary object. Optionally filters by org_id annotation or phase.

    Requires platform:admin permission.

    Args:
        org_id: If provided, only returns workflows whose metadata.annotations
                contain org_id matching this value.
        limit: Maximum number of workflows to retrieve (default 50, max 200).
        status: Argo phase filter — Succeeded, Failed, Running, or Error.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'runs' list and 'total' count.

    Raises:
        HTTPException: 502 if the Argo server is unreachable.
    """
    params: Dict[str, Any] = {"listOptions.limit": limit}
    if status:
        params["listOptions.fieldSelector"] = f"status.phase={status}"

    headers = get_argo_headers()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{ARGO_SERVER_URL}/api/v1/workflows/{ARGO_NAMESPACE}",
                params=params,
                headers=headers,
            )
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
    except httpx.TimeoutException as exc:
        logger.error("Argo server request timed out: %s", exc)
        raise HTTPException(status_code=502, detail="Argo server timed out")
    except httpx.HTTPStatusError as exc:
        logger.error("Argo server returned %s: %s", exc.response.status_code, exc)
        raise HTTPException(status_code=502, detail="Argo server error")
    except Exception as exc:
        logger.error("Failed to reach Argo server: %s", exc)
        raise HTTPException(status_code=502, detail="Argo server unreachable")

    runs: List[Dict[str, Any]] = []
    for wf in data.get("items") or []:
        meta = wf.get("metadata", {})
        wf_status = wf.get("status", {})
        annotations = meta.get("annotations") or {}

        started = wf_status.get("startedAt")
        finished = wf_status.get("finishedAt")

        runs.append(
            {
                "workflow_name": meta.get("name"),
                "org_id": annotations.get("org_id"),
                "scan_run_id": annotations.get("scan_run_id"),
                "status": wf_status.get("phase"),
                "started_at": started,
                "completed_at": finished,
                "duration_seconds": _parse_duration(started, finished),
                "failed_steps": _extract_failed_steps(wf_status.get("nodes")),
            }
        )

    # Client-side org_id filter (Argo API doesn't support annotation-based filtering)
    if org_id:
        runs = [r for r in runs if r.get("org_id") == org_id]

    return {"runs": runs, "total": len(runs)}
