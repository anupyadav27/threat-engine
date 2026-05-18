"""BFF view: /api_security page.

Fetches from the API Security engine report + findings endpoints and
returns the combined shape for the frontend dashboard.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Request

from ._auth import resolve_tenant_id

logger = logging.getLogger("api-gateway.bff.api_security")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_ENGINE_BASE = "http://engine-api-security.threat-engine-engines.svc.cluster.local"
_TIMEOUT = 15.0


def _fwd_headers(request: Request) -> Dict[str, str]:
    headers = {}
    auth = request.headers.get("X-Auth-Context")
    if auth:
        headers["X-Auth-Context"] = auth
    return headers


@router.get("/api_security")
async def get_api_security_view(request: Request):
    tenant_id = resolve_tenant_id(request)
    scan_run_id = request.query_params.get("scan_run_id", "latest")
    headers = _fwd_headers(request)

    report: Dict[str, Any] = {}
    findings: list = []

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                f"{_ENGINE_BASE}/api/v1/apisec/report/{scan_run_id}",
                headers=headers,
            )
            if r.status_code == 200:
                report = r.json()
        except Exception as exc:
            logger.warning("api_security report fetch failed: %s", exc)

        try:
            params: Dict[str, Any] = {"limit": 500}
            if tenant_id:
                params["tenant_id"] = tenant_id
            if scan_run_id != "latest":
                params["scan_run_id"] = scan_run_id
            r = await client.get(
                f"{_ENGINE_BASE}/api/v1/apisec/findings",
                params=params,
                headers=headers,
            )
            if r.status_code == 200:
                findings = r.json().get("findings", [])
        except Exception as exc:
            logger.warning("api_security findings fetch failed: %s", exc)

    return {
        "report": report,
        "findings": findings,
        "meta": {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "total": len(findings),
        },
    }
