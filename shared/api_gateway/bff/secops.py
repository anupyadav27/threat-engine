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

import json as _j
from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.secops import SecopsResponse
from ._cache import cache_key, cached_view, TTL_SECOPS, auth_level_from_header

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_SEV_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}


def _normalise_scan(raw: dict, source: str) -> dict:
    """Map a raw engine scan record to a consistent shape.

    Severity resolution order:
      1. Flat ``{col}_count`` columns from ``secops_latest_scan`` (new).
      2. Flat ``{col}`` columns (legacy SAST list endpoint).
      3. ``summary`` JSONB dict (legacy DAST list endpoint).
      Falls back to 0 when none of the above is present.

    Args:
        raw: Raw scan row dict from the engine.
        source: Scan type label, e.g. ``"sast"`` or ``"dast"``.

    Returns:
        Normalised scan dict with consistent field names.
    """
    summary = raw.get("summary") or {}
    if isinstance(summary, str):
        try:
            summary = _j.loads(summary)
        except Exception:
            summary = {}

    def _sev(col_key: str, summary_key: str) -> int:
        """Resolve severity count with three-tier fallback.

        Args:
            col_key: Flat column name, e.g. ``"critical_count"``.
            summary_key: Key inside ``summary`` JSONB, e.g. ``"critical"``.

        Returns:
            Integer count; 0 when none of the tiers is present.
        """
        if raw.get(col_key) is not None:
            return int(raw[col_key])
        if raw.get(summary_key) is not None:
            return int(raw[summary_key])
        return int(summary.get(summary_key) or 0)

    c = _sev("critical_count", "critical")
    h = _sev("high_count",     "high")
    m = _sev("medium_count",   "medium")
    lo = _sev("low_count",     "low")

    return {
        "scan_id":        raw.get("secops_scan_id") or raw.get("dast_scan_id") or raw.get("id", ""),
        "account_id":     raw.get("account_id", ""),
        "source":         source,
        "project":        raw.get("project_name") or raw.get("repo_url") or raw.get("target_url", "—"),
        "language":       raw.get("language", ""),
        "status":         (raw.get("status") or "unknown").lower(),
        "critical":       c,
        "high":           h,
        "medium":         m,
        "low":            lo,
        "total_findings": int(raw.get("total_findings") or raw.get("findings_count") or (c + h + m + lo)),
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


@router.get("/secops", response_model=SecopsResponse, response_model_exclude_none=False)
async def view_secops(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
):
    """
    Unified SecOps view — SAST + DAST scan summaries.
    SCA (SBOM) remains a direct frontend call (requires per-user API key).

    Calls ``GET /api/v1/secops/sast/latest-scans`` (one row per
    account_id/scan_type from ``secops_latest_scan``).  Falls back to the
    legacy ``/sast/scans`` + ``/dast/scans`` pair when the new endpoint is
    unavailable (graceful degradation during transition).
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)
    meta = BFFMeta("secops")

    ck = cache_key("secops", tenant_id, role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    qs = {"tenant_id": tenant_id}

    # Normalise — engine may return list, {latest_scans:[...]}, {scans:[...]},
    # {results:[...]}, or {data:[...]}.
    def _extract(raw: object) -> list:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            return (
                raw.get("latest_scans")
                or raw.get("scans")
                or raw.get("results")
                or raw.get("data")
                or []
            )
        return []

    # ── Primary: single call returning all scan types ─────────────────────────
    (raw_latest,) = await fetch_many(
        [("secops", "/api/v1/secops/sast/latest-scans", {"tenant_id": tenant_id})],
        auth_headers=fwd_headers,
    )

    if raw_latest is not None:
        # New path: engine guarantees one row per (account_id, scan_type)
        meta.record_engine("secops", "/api/v1/secops/sast/latest-scans", raw_latest)
        raw_all = _extract(raw_latest)
        sast_scans = [
            _normalise_scan(r, r.get("scan_type") or "sast")
            for r in raw_all
            if r.get("scan_type") in ("sast", "iac", None)
        ]
        dast_scans = [
            _normalise_scan(r, "dast")
            for r in raw_all
            if r.get("scan_type") == "dast"
        ]
    else:
        # ── Fallback: legacy two-endpoint path (graceful degradation) ─────────
        meta.warn("latest-scans endpoint unavailable; falling back to /sast/scans + /dast/scans")
        results = await fetch_many([
            ("secops", "/api/v1/secops/sast/scans", qs),
            ("secops", "/api/v1/secops/dast/scans", qs),
        ], auth_headers=fwd_headers)
        raw_sast, raw_dast = results

        meta.record_engine("secops", "/api/v1/secops/sast/scans", raw_sast)
        meta.record_engine("secops", "/api/v1/secops/dast/scans", raw_dast)
        if raw_sast is None:
            meta.warn("SAST scans endpoint returned no data")
        if raw_dast is None:
            meta.warn("DAST scans endpoint returned no data")

        sast_scans = [_normalise_scan(r, "sast") for r in _extract(raw_sast)]
        dast_scans = [_normalise_scan(r, "dast") for r in _extract(raw_dast)]

    all_scans = sast_scans + dast_scans

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

    result["_meta"] = meta.to_dict()
    cached_view(ck, result, ttl=TTL_SECOPS)
    return result
