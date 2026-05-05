"""BFF view: /ciem_identity — per-identity profile page (Stage 2).

Returns identity summary, finding list, activity heatmap data, and
hourly/DOW access patterns for a single CIEM principal.

Security: tenant_id is resolved from AuthContext (X-Auth-Context header),
never from the principal URL parameter. The principal parameter is a
filter hint only.
"""

import datetime
import json as _json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request

from ._auth import _parse_auth_context, resolve_tenant_id
from ._shared import ENGINE_URLS, _fetch_engine
import httpx

logger = logging.getLogger("api-gateway.bff.ciem_identity")
_jny03_audit_logger = logging.getLogger("api-gateway.audit")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

CIEM_URL = ENGINE_URLS.get("ciem", "http://engine-ciem")

_EMPTY: Dict[str, Any] = {
    "identity": {},
    "findings": [],
    "hourlyData": [],
    "dowData": [],
}


def _emit_audit(
    *,
    user_id: str,
    tenant_id: Optional[str],
    principal: str,
    result: int,
    request: Request,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Emit JSON-serialized audit log for CIEM identity profile access.

    SOC2 CC7.2 / ISO27001 A.12.4 / CSA CCM LOG-08.
    """
    top_arns: List[str] = []
    if findings:
        for f in findings[:50]:
            if not isinstance(f, dict):
                continue
            arn = f.get("actor_principal") or f.get("principal") or f.get("identity_arn")
            if arn and arn not in top_arns:
                top_arns.append(arn)
            if len(top_arns) >= 5:
                break
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "user_id": user_id,
        "tenant_id": tenant_id,
        "endpoint": "GET /api/v1/views/ciem_identity",
        "principal": principal,
        "result": result,
        "request_id": (
            request.headers.get("X-Request-Id")
            or request.headers.get("X-Correlation-Id")
            or getattr(request.state, "request_id", None)
        ),
        "top_5_identity_arns": top_arns,
    }
    _jny03_audit_logger.info(_json.dumps(payload))


@router.get("/ciem_identity")
async def view_ciem_identity(
    request: Request,
    principal: str = Query(..., description="URL-encoded principal ARN — filter hint only"),
    scan_run_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """BFF view for Stage 2 identity profile page.

    Permission gate: ciem:sensitive — analyst+ only. Viewer returns 403.
    All access (200 + 403) is audit-logged.

    Args:
        request: FastAPI Request — AuthContext header must be present.
        principal: The principal ARN to look up. Used as a query filter only.
            Tenant scoping comes from resolve_tenant_id(request), not this param.
        scan_run_id: Optional scan run filter.

    Returns:
        Dict with identity summary, findings list, and activity pattern data.
    """
    ctx = _parse_auth_context(request)
    tenant_id = resolve_tenant_id(request)
    user_id = getattr(ctx, "user_id", "unknown") if ctx is not None else "unknown"

    if ctx is None:
        _emit_audit(
            user_id=user_id, tenant_id=tenant_id, principal=principal,
            result=401, request=request,
        )
        raise HTTPException(status_code=401, detail="Authentication required")

    if "ciem:sensitive" not in (ctx.permissions or []):
        _emit_audit(
            user_id=user_id, tenant_id=tenant_id, principal=principal,
            result=403, request=request,
        )
        raise HTTPException(
            status_code=403,
            detail="You need Analyst access to view identity entitlements",
        )

    auth_ctx_header = (
        request.headers.get("X-Auth-Context")
        or getattr(request.state, "auth_header", None)
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Engine route map (these are the endpoints actually exposed by ciem api_server):
    #   - findings list:        GET /api/v1/ciem/findings?actor_principal=<arn>
    #   - identities summary:   GET /api/v1/ciem/identities
    #   - hourly+dow activity:  GET /api/v1/ciem/identities/{principal_encoded}/hourly-activity
    # The principal ARN is path-encoded for the activity endpoint; for findings
    # it is passed as a query param (engine uses LIKE — full ARN matches uniquely).
    findings_params: Dict[str, str] = {
        "actor_principal": principal,
        "limit": "100",
    }
    activity_params: Dict[str, str] = {}
    summary_params: Dict[str, str] = {"limit": "500"}
    if scan_run_id:
        findings_params["scan_run_id"] = scan_run_id
        activity_params["scan_run_id"] = scan_run_id
        summary_params["scan_run_id"] = scan_run_id

    principal_path = quote(principal, safe="")
    activity_path = f"/api/v1/ciem/identities/{principal_path}/hourly-activity"

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            findings_data = await _fetch_engine(
                client, "ciem", "/api/v1/ciem/findings",
                params=findings_params, auth_headers=fwd_headers,
            )
            activity_data = await _fetch_engine(
                client, "ciem", activity_path,
                params=activity_params, auth_headers=fwd_headers,
            )
            identities_data = await _fetch_engine(
                client, "ciem", "/api/v1/ciem/identities",
                params=summary_params, auth_headers=fwd_headers,
            )
    except Exception as exc:
        logger.warning("ciem_identity BFF fetch failed: %s", exc)
        # Constitution: no fallback — return canonical empty envelope
        _emit_audit(
            user_id=user_id, tenant_id=tenant_id, principal=principal,
            result=200, request=request,
        )
        return _EMPTY

    if findings_data is None and activity_data is None and identities_data is None:
        _emit_audit(
            user_id=user_id, tenant_id=tenant_id, principal=principal,
            result=200, request=request,
        )
        return _EMPTY

    findings = (findings_data or {}).get("findings", []) if isinstance(findings_data, dict) else (findings_data or [])
    hourly   = (activity_data or {}).get("hourly_distribution", []) if isinstance(activity_data, dict) else []
    dow      = (activity_data or {}).get("day_of_week_distribution", []) if isinstance(activity_data, dict) else []

    # Identity summary: pick the matching row from /identities response.
    identity: Dict[str, Any] = {}
    if isinstance(identities_data, dict):
        for row in identities_data.get("identities", []) or []:
            if isinstance(row, dict) and row.get("actor_principal") == principal:
                identity = row
                break
    if not identity:
        # Fallback summary derived from findings — keeps response useful even
        # if the principal is paginated out of the /identities top-N list.
        identity = {"actor_principal": principal, "total_findings": len(findings)}

    for f in findings:
        if isinstance(f, dict):
            f.pop("event_raw", None)
            f.pop("credential_ref", None)

    _emit_audit(
        user_id=user_id, tenant_id=tenant_id, principal=principal,
        result=200, request=request,
        findings=findings if isinstance(findings, list) else None,
    )

    return {
        "identity": identity,
        "findings": findings,
        "hourlyData": hourly,
        "dowData": dow,
    }
