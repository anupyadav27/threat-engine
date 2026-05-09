"""BFF view: /cnapp page — Cloud-Native Application Protection Platform.

Delegates to the CNAPP engine (/api/v1/cnapp/dashboard) which aggregates
all 7 CNAPP pillars in parallel:
  CSPM    — check + compliance engines
  CDR     — cdr + iam engines
  CWPP    — cwpp engine (containers, images, hosts, serverless, runtime)
  DSPM    — datasec engine
  Network — network-security engine
  Threat  — threat engine
  AppSec  — secops engine (SAST + DAST + SCA)

Single call: engine-cnapp /api/v1/cnapp/dashboard
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, is_empty_or_health, BFFMeta
from .schemas.cnapp import CNAPPResponse
from ._page_context import cnapp_page_context, cnapp_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/cnapp", response_model=CNAPPResponse, response_model_exclude_none=False)
async def view_cnapp(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the CNAPP unified view page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("cnapp")

    results = await fetch_many([
        ("cnapp", "/api/v1/cnapp/dashboard", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    cnapp_data = results[0]
    meta.record_engine("cnapp", "/api/v1/cnapp/dashboard", cnapp_data)
    if not isinstance(cnapp_data, dict) or is_empty_or_health(cnapp_data):
        cnapp_data = {}

    # ── Top-level scores ──────────────────────────────────────────────────────
    cnapp_score = safe_get(cnapp_data, "cnapp_posture_score", 0) or 0
    risk_band = safe_get(cnapp_data, "risk_band", "unknown")
    pillars = safe_get(cnapp_data, "pillars", {})

    # ── Per-pillar summary ────────────────────────────────────────────────────
    pillar_items = []
    for pid, pdata in pillars.items():
        score = pdata.get("posture_score")
        status = pdata.get("status", "unavailable")
        summary = pdata.get("summary", {})
        pillar_items.append({
            "id": pid,
            "name": _PILLAR_NAMES.get(pid, pid),
            "status": status,
            "posture_score": score,
            "risk_band": _score_band(score),
            "total_findings": (
                summary.get("total_findings")
                or summary.get("total_threats")
                or summary.get("total_checks")
                or 0
            ),
            "critical": (
                summary.get("critical")
                or summary.get("critical_findings")
                or 0
            ),
            "high": summary.get("high") or summary.get("high_findings") or 0,
            "summary": summary,
        })

    # ── Aggregate counts ──────────────────────────────────────────────────────
    total_findings = sum(p.get("total_findings", 0) for p in pillar_items if p["status"] == "ok")
    critical_total = sum(p.get("critical", 0) for p in pillar_items if p["status"] == "ok")
    pillars_ok = [p["id"] for p in pillar_items if p["status"] == "ok"]
    pillars_unavail = [p["id"] for p in pillar_items if p["status"] == "unavailable"]

    # ── Page context ──────────────────────────────────────────────────────────
    page_ctx = cnapp_page_context({
        "cnapp_posture_score": cnapp_score,
        "total_findings": total_findings,
        "critical": critical_total,
        "pillars_ok": len(pillars_ok),
        "risk_band": risk_band,
    })
    page_ctx["brief"] = (
        f"CNAPP posture score {cnapp_score}/100 — "
        f"{len(pillars_ok)} pillars active, {total_findings} findings, {critical_total} critical"
    )
    page_ctx["tabs"] = [
        {"id": "overview",  "label": "Overview"},
        {"id": "cspm",      "label": "CSPM"},
        {"id": "cdr",       "label": "CDR — Cloud Detection & Response"},
        {"id": "cwpp",      "label": "CWPP"},
        {"id": "dspm",      "label": "DSPM"},
        {"id": "network",   "label": "Network"},
        {"id": "threat",    "label": "Threat"},
        {"id": "appsec",    "label": "AppSec"},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": cnapp_filter_schema(),
        "kpiGroups": [
            {
                "title": "CNAPP Posture",
                "items": [
                    {"label": "CNAPP Score",       "value": cnapp_score, "suffix": "/100"},
                    {"label": "Risk Band",          "value": risk_band},
                    {"label": "Pillars Active",     "value": len(pillars_ok)},
                    {"label": "Total Findings",     "value": total_findings},
                    {"label": "Critical",           "value": critical_total},
                ],
            },
        ],
        # Top-level pillars alias for direct UI access (data.pillars or pillars both work)
        "pillars": pillar_items,
        "pillars_ok": pillars_ok,
        "pillars_unavailable": pillars_unavail,
        "cnapp_posture_score": cnapp_score,
        "risk_band": risk_band,
        "data": {
            "pillars": pillar_items,
            "pillars_ok": pillars_ok,
            "pillars_unavailable": pillars_unavail,
            "cnapp_posture_score": cnapp_score,
            "risk_band": risk_band,
            "raw": cnapp_data,
        },
        "_meta": meta.to_dict(),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

_PILLAR_NAMES = {
    "cspm":    "Cloud Security Posture (CSPM)",
    "cdr":     "CDR — Cloud Detection & Response",
    "cwpp":    "Workload Protection (CWPP)",
    "dspm":    "Data Security (DSPM)",
    "network": "Network Security",
    "threat":  "Threat Detection",
    "appsec":  "Application Security",
}


def _score_band(score) -> str:
    if score is None:
        return "unknown"
    s = float(score)
    if s >= 80:
        return "low"
    if s >= 60:
        return "medium"
    if s >= 40:
        return "high"
    return "critical"
