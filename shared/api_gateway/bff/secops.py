"""BFF view: /secops page.

Aggregates SAST + DAST scan lists from the secops engine into one
UI-ready response. SCA (SBOM) uses a separate API key so it stays
as a direct frontend call — only code-scan data is handled here.

GET /api/v1/views/secops
Returns:
  sastScans    – normalised list of SAST scan records
  dastScans    – normalised list of DAST scan records
  summary      – aggregate KPIs (totalScans, totalFindings, by_severity)
  kpiGroups    – standard KPI envelope for the page header
  scanTrend    – last 8 scans combined, oldest-first (for sparkline)
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get
from ._cache import cache_key, cached_view, TTL_SECOPS, auth_level_from_header

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_SEV_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}


def _normalise_scan(raw: dict, source: str) -> dict:
    """Map a raw engine scan record to a consistent shape."""
    return {
        "scan_id":        raw.get("secops_scan_id") or raw.get("dast_scan_id") or raw.get("id", ""),
        "source":         source,
        "project":        raw.get("project_name") or raw.get("repo_url") or raw.get("target_url", "—"),
        "language":       raw.get("language", ""),
        "status":         (raw.get("status") or "unknown").lower(),
        "critical":       int(raw.get("critical", 0)),
        "high":           int(raw.get("high", 0)),
        "medium":         int(raw.get("medium", 0)),
        "low":            int(raw.get("low", 0)),
        "total_findings": int(raw.get("total_findings") or raw.get("findings_count") or
                              (raw.get("critical", 0) + raw.get("high", 0) +
                               raw.get("medium", 0) + raw.get("low", 0))),
        "scan_timestamp": raw.get("scan_timestamp") or raw.get("created_at", ""),
        "duration_s":     raw.get("duration_seconds") or raw.get("duration", 0),
        "_raw":           raw,
    }


def _aggregate_kpis(scans: list) -> dict:
    completed = [s for s in scans if s["status"] == "completed"]
    total_findings = sum(s["total_findings"] for s in completed)
    critical = sum(s["critical"] for s in completed)
    high     = sum(s["high"]     for s in completed)
    medium   = sum(s["medium"]   for s in completed)
    low      = sum(s["low"]      for s in completed)

    # Risk score: weighted severity burden (0-10 scale like CVSS)
    if total_findings > 0:
        weight = critical * 10 + high * 5 + medium * 2 + low * 1
        max_weight = total_findings * 10
        risk_score = round((weight / max_weight) * 10, 1)
    else:
        risk_score = 0.0

    return {
        "totalScans":     len(scans),
        "completedScans": len(completed),
        "totalFindings":  total_findings,
        "critical":       critical,
        "high":           high,
        "medium":         medium,
        "low":            low,
        "riskScore":      risk_score,
    }


def _build_scan_trend(all_scans: list) -> list:
    """Last 8 completed scans across SAST+DAST, oldest-first."""
    completed = sorted(
        [s for s in all_scans if s["status"] == "completed"],
        key=lambda s: s["scan_timestamp"] or "",
    )[-8:]

    trend = []
    for s in completed:
        total = s["total_findings"]
        crit, high, med, low = s["critical"], s["high"], s["medium"], s["low"]
        if total > 0:
            weight = crit * 4 + high * 3 + med * 2 + low * 1
            pass_rate = max(0, 100 - round((weight / (total * 4)) * 100))
        else:
            pass_rate = 100

        ts = s["scan_timestamp"]
        label = ""
        if ts:
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                label = dt.strftime("%b %d")
            except Exception:
                label = ts[:10]

        trend.append({
            "date":      label or s["scan_id"][:8],
            "source":    s["source"],
            "total":     total,
            "critical":  crit,
            "high":      high,
            "medium":    med,
            "low":       low,
            "pass_rate": pass_rate,
        })
    return trend


@router.get("/secops")
async def view_secops(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
):
    """
    Unified SecOps view — SAST + DAST scan summaries.
    SCA (SBOM) remains a direct frontend call (requires per-user API key).
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("secops", tenant_id, role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    qs = {"tenant_id": tenant_id}

    results = await fetch_many([
        ("secops", "/api/v1/secops/sast/scans", qs),
        ("secops", "/api/v1/secops/dast/scans", qs),
    ], auth_headers=fwd_headers)

    raw_sast, raw_dast = results

    # Normalise — engine may return list or {scans: [...]} or {results: [...]}
    def _extract(raw) -> list:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            return raw.get("scans") or raw.get("results") or raw.get("data") or []
        return []

    sast_scans = [_normalise_scan(r, "sast") for r in _extract(raw_sast)]
    dast_scans = [_normalise_scan(r, "dast") for r in _extract(raw_dast)]
    all_scans  = sast_scans + dast_scans

    agg = _aggregate_kpis(all_scans)
    trend = _build_scan_trend(all_scans)

    result = {
        "sastScans": sast_scans,
        "dastScans": dast_scans,
        "summary":   agg,
        "scanTrend": trend,
        "kpiGroups": [
            {
                "title": "Code Scan Summary",
                "items": [
                    {"label": "Total Scans",     "value": agg["totalScans"]},
                    {"label": "Total Findings",  "value": agg["totalFindings"]},
                    {"label": "Critical",        "value": agg["critical"]},
                    {"label": "High",            "value": agg["high"]},
                    {"label": "Medium",          "value": agg["medium"]},
                    {"label": "Low",             "value": agg["low"]},
                    {"label": "Risk Score",      "value": agg["riskScore"], "suffix": "/10"},
                ],
            }
        ],
    }

    cached_view(ck, result, ttl=TTL_SECOPS)
    return result
