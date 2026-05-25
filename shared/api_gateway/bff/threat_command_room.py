"""BFF view: /threat-command-room page (Threat Command Room landing page).

Fans out to the threat engine /ui-data endpoint and reshapes the response
into a structured pulse_stats + scenarios payload for the Command Room layout.

Endpoint:
    GET /api/v1/views/threat-command-room
    Query params: tenant_id (required), provider (optional), account (optional),
                  region (optional), scan_run_id (default "latest")

Response shape:
    {
        "pulse_stats": { critical_count, high_count, medium_count, low_count,
                         composite_score, delta_count, delta_direction, new_today,
                         last_scan_at, last_scan_age_human, scan_status },
        "scenarios": [ { scenario_id, title, severity, risk_score, resource_uid,
                         resource_name, resource_type, csp, region, account_id,
                         signal_types, mitre_techniques, setup_summary,
                         last_scan_age, delta_since_last_scan, first_seen_at } ],
        "total": int,
        "scan_run_id": str
    }
"""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.threat_command_room import ThreatCommandRoomResponse
from ._cache import cache_key, cached_view, TTL_THREATS, auth_level_from_header

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Signal type derivation ────────────────────────────────────────────────────

SIGNAL_TYPE_MAP = {
    "IAMCredentialExposure": "identity",
    "ExcessivePermissions": "identity",
    "DataExposure": "misconfig",
    "PublicAccess": "misconfig",
    "NetworkExposure": "network",
    "VulnerabilityExploit": "vulnerability",
    "AIModelRisk": "ai_security",
}

_DEFAULT_SIGNAL_TYPE = "misconfig"


def _derive_signal_types(threat_category: str) -> List[str]:
    """Derive signal_types list from threat_category string."""
    if not threat_category:
        return [_DEFAULT_SIGNAL_TYPE]
    sig = SIGNAL_TYPE_MAP.get(threat_category, _DEFAULT_SIGNAL_TYPE)
    return [sig]


# ── Title construction ────────────────────────────────────────────────────────

def _build_title(detection: dict) -> str:
    """
    Build a natural-language scenario title from threat detection data.

    Priority:
      1. detection.description (if it reads as a sentence, not a raw rule_id)
      2. threat_category + resource_name template
      3. rule_id + resource_name fallback
    """
    description = detection.get("description", "").strip()
    resource_name = (
        detection.get("resource_name")
        or detection.get("resource_uid", "").split("/")[-1].split(":")[-1]
        or "resource"
    )
    threat_category = detection.get("threat_category") or detection.get("category") or ""
    rule_id = detection.get("rule_id") or detection.get("id") or ""

    # Use description if it looks like a human sentence (has spaces, not a rule_id pattern)
    if description and " " in description and not description.startswith("aws."):
        return description[:200]

    # Build from category
    if threat_category:
        # Convert camelCase / PascalCase to spaced words
        import re
        spaced = re.sub(r"([A-Z])", r" \1", threat_category).strip()
        return f"{spaced} affecting {resource_name}"

    # Fallback: rule_id readable form
    if rule_id:
        readable = rule_id.replace(".", " ").replace("_", " ").replace("-", " ")
        return f"{readable} on {resource_name}"

    return f"Threat scenario on {resource_name}"


# ── MITRE technique normalisation ─────────────────────────────────────────────

def _normalise_mitre(raw_techniques) -> List[dict]:
    """
    Normalise mitre_techniques to [{"id": "T1078", "name": "..."}] form.

    Accepts:
      - list of strings:  ["T1078", "T1530"]
      - list of dicts:    [{"id": "T1078", "name": "Valid Accounts"}, ...]
      - None / empty
    """
    if not raw_techniques:
        return []
    result = []
    for t in raw_techniques:
        if isinstance(t, str):
            result.append({"id": t, "name": ""})
        elif isinstance(t, dict):
            result.append({
                "id": t.get("id") or t.get("technique_id") or "",
                "name": t.get("name") or t.get("technique_name") or "",
            })
    return [r for r in result if r["id"]]


# ── Human-readable age ────────────────────────────────────────────────────────

def _human_age(ts: Optional[str]) -> str:
    """Return a human-readable time distance from now for an ISO timestamp."""
    if not ts:
        return "—"
    try:
        then = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff_secs = int((now - then).total_seconds())
        if diff_secs < 60:
            return "just now"
        if diff_secs < 3600:
            return f"{diff_secs // 60}m ago"
        if diff_secs < 86400:
            return f"{diff_secs // 3600}h ago"
        return f"{diff_secs // 86400}d ago"
    except Exception:
        return "—"


# ── Composite score ───────────────────────────────────────────────────────────

_SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _composite_score(scenarios: List[dict]) -> int:
    """
    Weighted average of scenario risk_scores, biased by severity weight.
    Returns 0-100 integer; 0 when list is empty.
    """
    if not scenarios:
        return 0
    total_weight = 0
    weighted_sum = 0.0
    for s in scenarios:
        score = s.get("risk_score") or 0
        sev = s.get("severity", "low")
        w = _SEVERITY_WEIGHTS.get(sev, 1)
        weighted_sum += score * w
        total_weight += w
    if total_weight == 0:
        return 0
    return min(100, round(weighted_sum / total_weight))


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.get("/threat-command-room", response_model=ThreatCommandRoomResponse, response_model_exclude_none=False)
async def view_threat_command_room(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
):
    """BFF view for the Threat Command Room landing page.

    Fans out to the threat engine and reshapes detection data into a structured
    pulse_stats + scenarios payload.  X-Auth-Context is forwarded verbatim so
    downstream RBAC enforcement applies.  credential_ref is never included in
    the response.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)
    meta = BFFMeta("threat_command_room")

    ck = cache_key(
        "threat-command-room",
        tenant_id,
        scan_run_id,
        provider or "",
        account or "",
        region or "",
        role_level=role_level,
    )
    cached = cached_view(ck)
    if cached is not None:
        return cached

    # Fan-out: attack-path engine ui-data (primary) + scan orchestration meta
    (threat_data,) = await fetch_many(
        [
            (
                "attack_path",
                "/api/v1/threat/ui-data",
                {
                    "tenant_id": tenant_id,
                    "scan_run_id": scan_run_id,
                    "limit": "2000",
                    "days": "90",
                },
            ),
        ],
        auth_headers=fwd_headers,
    )

    meta.record_engine("attack_path", "/api/v1/threat/ui-data", threat_data)
    if threat_data is None:
        meta.warn("Threat engine returned no data — scenarios will be empty")
    if not isinstance(threat_data, dict):
        threat_data = {}

    # ── Raw detections ─────────────────────────────────────────────────────
    raw_detections = safe_get(threat_data, "threats", []) or []
    engine_summary = safe_get(threat_data, "summary", {}) or {}
    scan_meta = safe_get(threat_data, "scan_meta", {}) or {}

    # Detect resolved scan_run_id from engine response
    resolved_scan_run_id = (
        safe_get(scan_meta, "scan_run_id")
        or scan_run_id
    )

    # ── Apply CSP / account / region filters ──────────────────────────────
    def _matches_filters(det: dict) -> bool:
        """Return True if detection passes the optional filters."""
        if provider and (det.get("provider") or "").upper() != provider.upper():
            csp_val = (det.get("csp") or det.get("provider") or "").upper()
            if csp_val != provider.upper():
                return False
        if account and (det.get("account_id") or det.get("account") or "") != account:
            return False
        if region and (det.get("region") or "") != region:
            return False
        return True

    filtered_raw = [d for d in raw_detections if _matches_filters(d)]

    # ── Build scenario objects ─────────────────────────────────────────────
    scenarios: List[dict] = []
    for det in filtered_raw:
        raw_sev = (det.get("severity") or "medium").lower()
        raw_score = det.get("risk_score") or det.get("riskScore") or 0

        # resource_name: prefer short name over full ARN / resource_uid
        resource_uid = det.get("resource_uid") or ""
        resource_name = (
            det.get("resource_name")
            or resource_uid.split("/")[-1].split(":")[-1]
            or resource_uid
        )

        # CSP: prefer det.csp, then det.provider, then upper-case account prefix
        csp = (det.get("csp") or det.get("provider") or "").lower()

        # Signal types from threat_category
        threat_category = det.get("threat_category") or det.get("category") or ""
        signal_types = _derive_signal_types(threat_category)

        # MITRE techniques
        raw_mitre = (
            det.get("mitre_techniques")
            or det.get("mitreTechniques")
            or []
        )
        mitre_techniques = _normalise_mitre(raw_mitre)

        # Setup summary — use description, fall back to threat_category desc
        setup_summary = (det.get("description") or "").strip()
        if not setup_summary and threat_category:
            setup_summary = f"Threat category: {threat_category.replace('_', ' ')} detected on {resource_name}."

        # Timestamps
        first_seen_at = (
            det.get("first_seen_at")
            or det.get("detected_at")
            or det.get("detected")
            or ""
        )
        last_seen_at = (
            det.get("last_seen_at")
            or det.get("last_updated")
            or ""
        )

        scenario = {
            "scenario_id": (
                det.get("id")
                or det.get("detection_id")
                or det.get("finding_id")
                or det.get("threat_id")
                or ""
            ),
            "title": _build_title(det),
            "severity": raw_sev,
            "risk_score": int(raw_score),
            "resource_uid": resource_uid,
            "resource_name": resource_name,
            "resource_type": det.get("resource_type") or det.get("resourceType") or "",
            "csp": csp,
            "region": det.get("region") or "",
            "account_id": det.get("account_id") or det.get("account") or "",
            "signal_types": signal_types,
            "mitre_techniques": mitre_techniques,
            "setup_summary": setup_summary[:500] if setup_summary else "",
            "last_scan_age": _human_age(last_seen_at or first_seen_at),
            "delta_since_last_scan": 0,
            "first_seen_at": first_seen_at,
            "attack_chain":  det.get("attack_chain") or det.get("attack_path") or [],
            "top_findings":  det.get("top_findings") or det.get("contributing_findings") or [],
        }
        scenarios.append(scenario)

    # Sort descending by risk_score then severity weight
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    scenarios.sort(
        key=lambda s: (-s["risk_score"], _SEV_ORDER.get(s["severity"], 9))
    )

    total = len(scenarios)

    # ── Severity counts ────────────────────────────────────────────────────
    # Prefer engine summary (covers unfiltered totals) when no filters active
    if engine_summary and not (provider or account or region):
        critical_count = int(
            engine_summary.get("critical", 0)
            or sum(1 for s in scenarios if s["severity"] == "critical")
        )
        high_count = int(
            engine_summary.get("high", 0)
            or sum(1 for s in scenarios if s["severity"] == "high")
        )
        medium_count = int(
            engine_summary.get("medium", 0)
            or sum(1 for s in scenarios if s["severity"] == "medium")
        )
        low_count = int(
            engine_summary.get("low", 0)
            or sum(1 for s in scenarios if s["severity"] == "low")
        )
    else:
        critical_count = sum(1 for s in scenarios if s["severity"] == "critical")
        high_count = sum(1 for s in scenarios if s["severity"] == "high")
        medium_count = sum(1 for s in scenarios if s["severity"] == "medium")
        low_count = sum(1 for s in scenarios if s["severity"] == "low")

    # ── Composite score ────────────────────────────────────────────────────
    composite_score = _composite_score(scenarios)

    # ── Scan timing ───────────────────────────────────────────────────────
    # last_scan_at: from scan_meta or fall back to most recent first_seen_at
    last_scan_at = safe_get(scan_meta, "last_scan_at") or safe_get(scan_meta, "completed_at") or ""
    if not last_scan_at and scenarios:
        timestamps = [
            s["first_seen_at"] for s in scenarios if s["first_seen_at"]
        ]
        if timestamps:
            last_scan_at = max(timestamps)

    last_scan_age_human = _human_age(last_scan_at) if last_scan_at else None

    # ── Delta / new_today (best-effort from engine summary) ──────────────
    delta_count = int(safe_get(engine_summary, "delta_count") or 0)
    delta_direction = safe_get(engine_summary, "delta_direction") or (
        "up" if delta_count > 0 else "down" if delta_count < 0 else "flat"
    )
    new_today = int(safe_get(engine_summary, "new_today") or 0)
    if not new_today and last_scan_at:
        today_prefix = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        new_today = sum(
            1 for s in scenarios
            if s.get("first_seen_at", "").startswith(today_prefix)
        )

    # ── Scan status ───────────────────────────────────────────────────────
    scan_status = safe_get(scan_meta, "status") or "completed"

    # ── Trend points: per-scan chart data with chart dataKeys ───────────────
    raw_trend = safe_get(threat_data, "scan_trend") or safe_get(threat_data, "trend", []) or []
    trend_points = []
    for pt in (raw_trend if isinstance(raw_trend, list) else []):
        sev_pt = pt.get("by_severity") or {}
        trend_points.append({
            "date":        pt.get("scan_date") or pt.get("date", ""),
            "critical":    sev_pt.get("critical", pt.get("critical", 0)),
            "high":        sev_pt.get("high",     pt.get("high",     0)),
            "medium":      sev_pt.get("medium",   pt.get("medium",   0)),
            "low":         sev_pt.get("low",      pt.get("low",      0)),
            "risk_score":  pt.get("risk_score") or pt.get("composite_score", 0),
            "total":       pt.get("total_findings") or pt.get("total", 0),
            "passRate":    pt.get("pass_rate") or pt.get("passRate", 0),
            "tactics":     pt.get("tactics") or [],
        })
    # Synthetic single point if engine has no trend data
    if not trend_points:
        trend_points = [{
            "date": last_scan_at or "",
            "critical": critical_count, "high": high_count,
            "medium": medium_count, "low": low_count,
            "risk_score": composite_score, "total": total,
            "passRate": 0, "tactics": [],
        }]

    # ── Build response (no credential_ref) ───────────────────────────────
    result = {
        "pulse_stats": {
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "composite_score": composite_score,
            "delta_count": abs(delta_count),
            "delta_direction": delta_direction,
            "new_today": new_today,
            "last_scan_at": last_scan_at or None,
            "last_scan_age_human": last_scan_age_human,
            "last_scan_age": last_scan_age_human,
            "scan_status": scan_status,
        },
        # Top-level flat aliases (UI may access both paths)
        "critical":       critical_count,
        "high":           high_count,
        "medium":         medium_count,
        "low":            low_count,
        "risk_score":     composite_score,
        "composite_score":composite_score,
        "critical_count": critical_count,
        "high_count":     high_count,
        "medium_count":   medium_count,
        "low_count":      low_count,
        "new_today":      new_today,
        "delta_count":    abs(delta_count),
        "delta_direction":delta_direction,
        "last_scan_at":   last_scan_at or None,
        "last_scan_age":  last_scan_age_human,
        "last_scan_age_human": last_scan_age_human,
        "scan_status":    scan_status,
        "scenarios":      scenarios,
        "count":          total,
        "total":          total,
        "scan_run_id":    resolved_scan_run_id,
        "finding_id":     scenarios[0].get("scenario_id", "") if scenarios else "",
        "scenario_id":    scenarios[0].get("scenario_id", "") if scenarios else "",
        "trendPoints":    trend_points,
        "brief":          f"{critical_count} critical, {high_count} high — {total} total detections",
        "details":        {"scan_run_id": resolved_scan_run_id, "scan_status": scan_status},
        "_meta":          meta.to_dict(),
    }

    cached_view(ck, result, ttl=TTL_THREATS)
    return result
