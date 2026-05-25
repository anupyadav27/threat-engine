"""BFF views: threat-posture-delta and threat-trend pages (THREAT-UI-03).

Two endpoints:
    GET /api/v1/views/threat-posture-delta
        Compares two scan runs side-by-side and returns:
        - summary delta (threat score, scenario count, critical count, ATT&CK coverage)
        - categorised scenario lists (new, resolved, escalated, de-escalated)
        - available scan list for the selector dropdowns

    GET /api/v1/views/threat-trend
        Returns per-scan-run time-series data for the trend chart.
        Accepts: days (7 | 30 | 90, default 90), provider (optional filter).

RBAC: threats:read permission required (viewer role can access).
Security:
    - X-Auth-Context forwarded verbatim to all downstream engine calls.
    - credential_ref is never included in responses.
    - Cache key includes role_level to prevent cross-role data bleed (STRIDE).
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get
from ._cache import cache_key, cached_view, TTL_THREATS, auth_level_from_header

logger = logging.getLogger("api-gateway.bff")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Severity order ─────────────────────────────────────────────────────────────

_SEV_ORDER: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_WEIGHTS: Dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ── Helper: composite score ────────────────────────────────────────────────────

def _composite_score(scenarios: List[dict]) -> int:
    """Compute a weighted composite risk score (0-100) from a scenario list.

    Args:
        scenarios: List of scenario dicts with ``severity`` and ``risk_score`` fields.

    Returns:
        Weighted average score clamped to [0, 100].
    """
    if not scenarios:
        return 0
    total_w = 0
    weighted = 0.0
    for s in scenarios:
        score = s.get("risk_score") or 0
        w = _SEV_WEIGHTS.get(s.get("severity", "low"), 1)
        weighted += score * w
        total_w += w
    return min(100, round(weighted / total_w)) if total_w else 0


# ── Helper: ATT&CK coverage percentage ────────────────────────────────────────

def _attack_coverage_pct(scenarios: List[dict]) -> float:
    """Estimate ATT&CK tactic coverage percentage from scenario list.

    Args:
        scenarios: List of scenario dicts with optional ``mitre_techniques`` field.

    Returns:
        Percentage of 14 main ATT&CK for Cloud tactics represented (0.0-100.0).
    """
    _ALL_TACTICS = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact", "Resource Development",
        "Reconnaissance", "Command and Control",
    }
    tactics_seen: set = set()
    for s in scenarios:
        for t in s.get("mitre_techniques") or []:
            tac = t.get("tactic") or t.get("name") or ""
            if tac:
                tactics_seen.add(tac)
    if not _ALL_TACTICS:
        return 0.0
    return round(len(tactics_seen & _ALL_TACTICS) / len(_ALL_TACTICS) * 100, 1)


# ── Helper: build scenario key ─────────────────────────────────────────────────

def _scenario_key(s: dict) -> str:
    """Unique join key: resource_uid + threat_category (or rule_id fallback).

    Args:
        s: Raw detection/threat dict from the engine.

    Returns:
        String key used to match the same logical scenario across scan runs.
    """
    uid = s.get("resource_uid") or s.get("resource_id") or ""
    cat = (
        s.get("threat_category")
        or s.get("category")
        or s.get("rule_id")
        or ""
    )
    return f"{uid}::{cat}"


# ── Helper: date label ─────────────────────────────────────────────────────────

def _date_label(ts: Optional[str]) -> str:
    """Format an ISO timestamp as a short human label (e.g. 'May 01').

    Args:
        ts: ISO 8601 timestamp string or None.

    Returns:
        Human-readable short date or 'Unknown'.
    """
    if not ts:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%b %d")
    except Exception:
        return ts[:10] if len(ts) >= 10 else "Unknown"


# ── Helper: normalize raw detection to scenario shape ─────────────────────────

def _normalize_scenario(det: dict) -> dict:
    """Normalize a raw threat engine detection dict into a scenario dict.

    Strips credential_ref and any internal engine fields.  Mirrors the
    normalisation done in threat_command_room.py.

    Args:
        det: Raw detection dict from threat engine ``/api/v1/threat/ui-data``.

    Returns:
        Normalized scenario dict safe to return to the frontend.
    """
    resource_uid = det.get("resource_uid") or ""
    resource_name = (
        det.get("resource_name")
        or resource_uid.split("/")[-1].split(":")[-1]
        or resource_uid
    )
    severity = (det.get("severity") or "medium").lower()
    risk_score = int(det.get("risk_score") or det.get("riskScore") or 0)

    mitre_raw = det.get("mitre_techniques") or det.get("mitreTechniques") or []
    mitre: List[dict] = []
    for t in mitre_raw:
        if isinstance(t, str):
            mitre.append({"id": t, "name": "", "tactic": ""})
        elif isinstance(t, dict):
            mitre.append({
                "id": t.get("id") or t.get("technique_id") or "",
                "name": t.get("name") or t.get("technique_name") or "",
                "tactic": t.get("tactic") or t.get("phase") or "",
            })

    return {
        "scenario_id": (
            det.get("id")
            or det.get("detection_id")
            or det.get("finding_id")
            or det.get("threat_id")
            or ""
        ),
        "title": (
            det.get("description", "").strip()
            or det.get("threat_category", "")
            or "Threat scenario"
        )[:200],
        "severity": severity,
        "risk_score": risk_score,
        "resource_uid": resource_uid,
        "resource_name": resource_name,
        "resource_type": det.get("resource_type") or det.get("resourceType") or "",
        "csp": (det.get("csp") or det.get("provider") or "").lower(),
        "region": det.get("region") or "",
        "account_id": det.get("account_id") or det.get("account") or "",
        "threat_category": det.get("threat_category") or det.get("category") or "",
        "mitre_techniques": mitre,
        "first_seen_at": det.get("first_seen_at") or det.get("detected_at") or "",
        "last_seen_at": det.get("last_seen_at") or det.get("last_updated") or "",
        # credential_ref deliberately excluded
    }


# ── Helper: build available_scans from threat reports list ────────────────────

def _build_available_scans(reports: List[dict]) -> List[dict]:
    """Build the scan selector list from a list of threat report metadata.

    Args:
        reports: List of report dicts each containing ``scan_run_id`` and
                 ``generated_at`` or ``completed_at``.

    Returns:
        List of scan descriptors sorted newest-first with ``label`` field.
    """
    scans = []
    for r in reports:
        sid = r.get("scan_run_id") or r.get("scan_run_id") or ""
        ts = r.get("completed_at") or r.get("generated_at") or r.get("created_at") or ""
        if not sid:
            continue
        scans.append({
            "scan_run_id": sid,
            "completed_at": ts,
            "label": _date_label(ts),
        })
    # Deduplicate by scan_run_id, keep newest-first
    seen: set = set()
    unique: List[dict] = []
    for s in scans:
        if s["scan_run_id"] not in seen:
            seen.add(s["scan_run_id"])
            unique.append(s)
    # Sort newest first (ISO timestamp string comparison is valid for RFC3339)
    unique.sort(key=lambda x: x["completed_at"] or "", reverse=True)
    return unique


# ── Helper: compute delta between two scenario sets ───────────────────────────

def _compute_delta(
    scenarios_a: List[dict],
    scenarios_b: List[dict],
) -> Tuple[List[dict], List[dict], List[dict], List[dict]]:
    """Classify scenarios into new / resolved / escalated / de-escalated.

    Matching is done on ``_scenario_key()`` (resource_uid + threat_category).
    Escalated = present in both scans with higher risk_score in scan B.
    De-escalated = present in both scans with lower risk_score in scan B.

    Args:
        scenarios_a: Normalized scenarios from the older scan (scan A).
        scenarios_b: Normalized scenarios from the newer scan (scan B).

    Returns:
        Tuple of (new, resolved, escalated, de_escalated) scenario lists.
        Escalated/de-escalated items include extra fields:
            risk_score_a, risk_score_b, risk_score_delta.
    """
    map_a: Dict[str, dict] = {}
    for s in scenarios_a:
        k = _scenario_key(s)
        # Keep highest risk_score if key collides
        if k not in map_a or s["risk_score"] > map_a[k]["risk_score"]:
            map_a[k] = s

    map_b: Dict[str, dict] = {}
    for s in scenarios_b:
        k = _scenario_key(s)
        if k not in map_b or s["risk_score"] > map_b[k]["risk_score"]:
            map_b[k] = s

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    new_scenarios: List[dict] = [map_b[k] for k in (keys_b - keys_a)]
    resolved_scenarios: List[dict] = [map_a[k] for k in (keys_a - keys_b)]

    escalated: List[dict] = []
    de_escalated: List[dict] = []
    for k in keys_a & keys_b:
        s_a = map_a[k]
        s_b = map_b[k]
        delta = s_b["risk_score"] - s_a["risk_score"]
        if delta > 0:
            escalated.append({
                **s_b,
                "risk_score_a": s_a["risk_score"],
                "risk_score_b": s_b["risk_score"],
                "risk_score_delta": delta,
            })
        elif delta < 0:
            de_escalated.append({
                **s_b,
                "risk_score_a": s_a["risk_score"],
                "risk_score_b": s_b["risk_score"],
                "risk_score_delta": delta,
            })

    # Sort each list descending by risk_score
    for lst in (new_scenarios, resolved_scenarios, escalated, de_escalated):
        lst.sort(key=lambda s: (-s["risk_score"], _SEV_ORDER.get(s["severity"], 9)))

    return new_scenarios, resolved_scenarios, escalated, de_escalated


# ── Endpoint 1: Posture Delta ─────────────────────────────────────────────────

@router.get("/threat-posture-delta")
async def view_threat_posture_delta(
    request: Request,
    scan_a: Optional[str] = Query(None, description="Older scan_run_id (defaults to 2nd most recent)"),
    scan_b: Optional[str] = Query(None, description="Newer scan_run_id (defaults to most recent)"),
    provider: Optional[str] = Query(None, description="Optional CSP filter"),
) -> Dict[str, Any]:
    """BFF view for the Trends & Posture Delta page comparison panel.

    Fetches both scan runs in parallel from the threat engine, then computes
    per-scenario classification (new / resolved / escalated / de-escalated)
    and summary KPI deltas.

    Returns a single-scan-mode response when fewer than 2 scans are available.
    X-Auth-Context is forwarded to downstream engines; credential_ref is never
    included in responses.

    Args:
        request: FastAPI request for auth header extraction.
        scan_a: Older scan_run_id for comparison baseline.
        scan_b: Newer scan_run_id for comparison target.
        provider: Optional CSP filter applied to both scan datasets.

    Returns:
        Posture delta response dict.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    # Step 1: fetch the scan run list so we can resolve defaults
    (scan_runs_data,) = await fetch_many(
        [
            (
                "onboarding",
                "/api/v1/scan-runs",
                {"tenant_id": tenant_id, "status": "completed", "limit": "30"},
            )
        ],
        auth_headers=fwd_headers,
    )
    raw_runs: List[dict] = []
    if isinstance(scan_runs_data, dict):
        raw_runs = scan_runs_data.get("scan_runs") or []
    elif isinstance(scan_runs_data, list):
        raw_runs = scan_runs_data

    available_scans = _build_available_scans(raw_runs)

    # Resolve scan_b → most recent, scan_a → second most recent
    if not scan_b and available_scans:
        scan_b = available_scans[0]["scan_run_id"]
    if not scan_a and len(available_scans) >= 2:
        scan_a = available_scans[1]["scan_run_id"]

    # Single-scan mode: only one (or zero) scans available
    if not scan_a or not scan_b or scan_a == scan_b:
        single_scan_scenarios: List[dict] = []
        single_score = 0
        single_ts = ""
        if scan_b:
            (single_data,) = await fetch_many(
                [
                    (
                        "attack_path",
                        "/api/v1/threat/ui-data",
                        {"tenant_id": tenant_id, "scan_run_id": scan_b, "limit": "2000"},
                    )
                ],
                auth_headers=fwd_headers,
            )
            if isinstance(single_data, dict):
                raw_det = safe_get(single_data, "threats", []) or []
                single_scan_scenarios = [_normalize_scenario(d) for d in raw_det]
                single_score = _composite_score(single_scan_scenarios)
                single_ts = (
                    safe_get(single_data, "scan_meta.completed_at")
                    or safe_get(single_data, "scan_meta.last_scan_at")
                    or ""
                )

        return {
            "single_scan_mode": True,
            "scan_b": {
                "scan_run_id": scan_b or "",
                "completed_at": single_ts,
                "label": _date_label(single_ts),
            },
            "summary": {
                "threat_score_b": single_score,
                "scenarios_b": len(single_scan_scenarios),
                "critical_b": sum(1 for s in single_scan_scenarios if s["severity"] == "critical"),
                "attack_coverage_pct_b": _attack_coverage_pct(single_scan_scenarios),
            },
            "new_scenarios": [],
            "resolved_scenarios": [],
            "escalated_scenarios": [],
            "deescalated_scenarios": [],
            "available_scans": available_scans,
        }

    # Cache check (both scan IDs known)
    ck = cache_key(
        "threat-posture-delta",
        tenant_id,
        scan_a,
        scan_b,
        provider or "",
        role_level=role_level,
    )
    cached = cached_view(ck)
    if cached is not None:
        return cached

    # Step 2: fetch both scan runs in parallel
    threat_a_data, threat_b_data = await fetch_many(
        [
            (
                "attack_path",
                "/api/v1/threat/ui-data",
                {"tenant_id": tenant_id, "scan_run_id": scan_a, "limit": "2000"},
            ),
            (
                "attack_path",
                "/api/v1/threat/ui-data",
                {"tenant_id": tenant_id, "scan_run_id": scan_b, "limit": "2000"},
            ),
        ],
        auth_headers=fwd_headers,
    )

    # Normalize
    raw_a = safe_get(threat_a_data or {}, "threats", []) or []
    raw_b = safe_get(threat_b_data or {}, "threats", []) or []

    def _filter_provider(scenarios: List[dict]) -> List[dict]:
        if not provider:
            return scenarios
        return [
            s for s in scenarios
            if (s.get("csp") or s.get("provider") or "").lower() == provider.lower()
        ]

    scenarios_a = _filter_provider([_normalize_scenario(d) for d in raw_a])
    scenarios_b = _filter_provider([_normalize_scenario(d) for d in raw_b])

    # Scan metadata
    meta_a = safe_get(threat_a_data or {}, "scan_meta", {}) or {}
    meta_b = safe_get(threat_b_data or {}, "scan_meta", {}) or {}
    ts_a = (
        meta_a.get("completed_at")
        or meta_a.get("last_scan_at")
        or ""
    )
    ts_b = (
        meta_b.get("completed_at")
        or meta_b.get("last_scan_at")
        or ""
    )

    # KPI computation
    score_a = _composite_score(scenarios_a)
    score_b = _composite_score(scenarios_b)
    crit_a = sum(1 for s in scenarios_a if s["severity"] == "critical")
    crit_b = sum(1 for s in scenarios_b if s["severity"] == "critical")
    cov_a = _attack_coverage_pct(scenarios_a)
    cov_b = _attack_coverage_pct(scenarios_b)

    # Delta classification
    new_sc, resolved_sc, escalated_sc, de_escalated_sc = _compute_delta(
        scenarios_a, scenarios_b
    )

    net_change = len(scenarios_b) - len(scenarios_a)

    result: Dict[str, Any] = {
        "single_scan_mode": False,
        "scan_a": {
            "scan_run_id": scan_a,
            "completed_at": ts_a,
            "label": _date_label(ts_a),
        },
        "scan_b": {
            "scan_run_id": scan_b,
            "completed_at": ts_b,
            "label": _date_label(ts_b),
        },
        "summary": {
            "threat_score_a": score_a,
            "threat_score_b": score_b,
            "threat_score_delta": score_b - score_a,
            "scenarios_a": len(scenarios_a),
            "scenarios_b": len(scenarios_b),
            "scenarios_delta": len(scenarios_b) - len(scenarios_a),
            "critical_a": crit_a,
            "critical_b": crit_b,
            "critical_delta": crit_b - crit_a,
            "attack_coverage_pct_a": cov_a,
            "attack_coverage_pct_b": cov_b,
            "attack_coverage_delta": round(cov_b - cov_a, 1),
            "new_count": len(new_sc),
            "resolved_count": len(resolved_sc),
            "net_change": net_change,
        },
        "new_scenarios": new_sc,
        "resolved_scenarios": resolved_sc,
        "escalated_scenarios": escalated_sc,
        "deescalated_scenarios": de_escalated_sc,
        "available_scans": available_scans,
    }

    cached_view(ck, result, ttl=TTL_THREATS)
    return result


# ── Endpoint 2: Trend Data ────────────────────────────────────────────────────

@router.get("/threat-trend")
async def view_threat_trend(
    request: Request,
    days: int = Query(90, description="Lookback window in days (7 | 30 | 90)"),
    provider: Optional[str] = Query(None, description="Optional CSP filter"),
) -> Dict[str, Any]:
    """BFF view for the Trends & Posture 90-day trend chart.

    Calls the threat engine analytics/trend endpoint, normalises the response
    into the per-scan-run data points expected by ThreatTrendChart.jsx.

    Each data point corresponds to one completed scan run and carries:
    date, scan_run_id, risk_score, critical/high/medium/low counts, total,
    and optionally a ``tactics`` map.

    Args:
        request: FastAPI request for auth header extraction.
        days: Lookback window in days (7, 30, or 90).
        provider: Optional CSP filter.

    Returns:
        Trend data response dict.
    """
    tenant_id = resolve_tenant_id(request)
    days = max(7, min(days, 90))  # clamp to allowed range

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key(
        "threat-trend",
        tenant_id,
        str(days),
        provider or "",
        role_level=role_level,
    )
    cached = cached_view(ck)
    if cached is not None:
        return cached

    # Fan-out: threat analytics trend + scan runs list (for scan_run_id per date)
    # TODO: decommission after engine-threat teardown — no attack-path equivalent yet
    threat_trend_data, scan_runs_data = await fetch_many(
        [
            (
                "threat",
                "/api/v1/threat/analytics/trend",
                {
                    "tenant_id": tenant_id,
                    "days": str(days),
                    **({"provider": provider} if provider else {}),
                },
            ),
            (
                "onboarding",
                "/api/v1/scan-runs",
                {"tenant_id": tenant_id, "status": "completed", "limit": "100"},
            ),
        ],
        auth_headers=fwd_headers,
    )

    # Build a date → scan_run_id lookup from the scan runs list
    date_to_scan: Dict[str, str] = {}
    raw_runs: List[dict] = []
    if isinstance(scan_runs_data, dict):
        raw_runs = scan_runs_data.get("scan_runs") or []
    elif isinstance(scan_runs_data, list):
        raw_runs = scan_runs_data

    for run in raw_runs:
        ts = run.get("completed_at") or run.get("created_at") or ""
        sid = run.get("scan_run_id") or ""
        if ts and sid:
            date_str = ts[:10]
            # Keep most recent scan for each date
            if date_str not in date_to_scan:
                date_to_scan[date_str] = sid

    # Normalise trend data from engine response
    raw_trend: List[dict] = []
    if isinstance(threat_trend_data, dict):
        raw_trend = threat_trend_data.get("trend_data") or []

    # Calculate cutoff date
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    trend_points: List[dict] = []
    for point in raw_trend:
        date_str = point.get("date") or ""
        if not date_str:
            continue
        # Skip points outside the requested window
        try:
            pt_date = datetime.fromisoformat(date_str)
            if pt_date.tzinfo is None:
                pt_date = pt_date.replace(tzinfo=timezone.utc)
            if pt_date < cutoff:
                continue
        except Exception:
            pass

        # Severity counts — engine uses ``by_severity`` nested dict
        by_sev = point.get("by_severity") or {}
        critical = int(by_sev.get("critical", 0) or point.get("critical", 0))
        high = int(by_sev.get("high", 0) or point.get("high", 0))
        medium = int(by_sev.get("medium", 0) or point.get("medium", 0))
        low = int(by_sev.get("low", 0) or point.get("low", 0))
        total = int(
            point.get("total_threats")
            or point.get("total", 0)
            or (critical + high + medium + low)
        )

        # Simple composite risk_score derived from severity distribution
        w_sum = critical * 4 + high * 3 + medium * 2 + low * 1
        risk_score = min(100, round(w_sum * 100 / (total * 4))) if total else 0

        # Tactics map — from ``by_category`` if available (best proxy from engine)
        tactics: Optional[Dict[str, int]] = None
        by_cat = point.get("by_category") or {}
        if by_cat and isinstance(by_cat, dict):
            tactics = {k: int(v) for k, v in by_cat.items() if v}

        dp: Dict[str, Any] = {
            "date": date_str,
            "scan_run_id": date_to_scan.get(date_str, ""),
            "risk_score": risk_score,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": total,
        }
        if tactics:
            dp["tactics"] = tactics

        trend_points.append(dp)

    # If the engine returned nothing, the chart will render an empty state gracefully
    result = {
        "trend_data": trend_points,
        "days": days,
        "total_scans": len(trend_points),
    }

    cached_view(ck, result, ttl=TTL_THREATS)
    return result
