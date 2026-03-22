"""BFF view: /threats/timeline — Activity Timeline page.

Returns a chronological audit trail of threat state changes:
detections, assignments, investigations, resolutions, suppressions.

Pulls from threat_detections (via the threat engine's /threats endpoint)
and scan orchestration to construct a timeline event feed.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse a timestamp string to datetime, returning None on failure."""
    if not ts_str:
        return None
    try:
        # Handle various formats
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(ts_str[:26].rstrip("Z"), fmt.replace("%z", "")).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # Fallback: try dateutil-style
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


@router.get("/threats/timeline")
async def threat_timeline_view(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    limit: int = Query(200, le=500),
):
    """Aggregate threat activity events into a timeline.

    Pulls from threat detections via the threat engine and scan
    orchestration to construct a chronological event feed.
    """

    # Use threat engine's ui-data endpoint (returns detections with timestamps)
    threat_params = {
        "tenant_id": tenant_id,
        "limit": str(limit),
        "days": "30",
    }

    threat_data, scan_data = await fetch_many([
        ("threat", "/api/v1/threat/ui-data", threat_params),
        ("onboarding", "/api/v1/cloud-accounts/scans/recent", {"tenant_id": tenant_id}),
    ])

    if not isinstance(threat_data, dict):
        threat_data = {}
    if not isinstance(scan_data, dict):
        scan_data = {}

    # Build events from threat detections
    events = []
    raw_threats = safe_get(threat_data, "threats", []) or []
    if not isinstance(raw_threats, list):
        raw_threats = safe_get(threat_data, "data", []) or safe_get(threat_data, "detections", []) or []
    if not isinstance(raw_threats, list):
        raw_threats = []

    # Track resolution times for avg computation
    resolution_times_hours = []

    for i, t in enumerate(raw_threats[:limit]):
        threat_id = (
            t.get("detection_id") or t.get("finding_id")
            or t.get("id") or f"t-{i}"
        )
        title = (
            t.get("title") or t.get("rule_name")
            or t.get("detection_type") or "Unknown threat"
        )
        severity = (t.get("severity") or "medium").lower()
        acct = t.get("account_id") or t.get("account") or ""
        detected_at = (
            t.get("detected_at") or t.get("detection_timestamp")
            or t.get("first_seen_at") or t.get("created_at")
            or t.get("detected") or ""
        )
        updated_at = (
            t.get("last_seen_at") or t.get("updated_at") or ""
        )
        status = (t.get("status") or t.get("verdict") or "active").lower()
        technique = ""
        mitre_techniques = t.get("mitre_techniques") or []
        if isinstance(mitre_techniques, list) and mitre_techniques:
            first = mitre_techniques[0]
            if isinstance(first, str):
                technique = first
            elif isinstance(first, dict):
                technique = first.get("technique_id") or first.get("id") or ""
        elif isinstance(mitre_techniques, str):
            technique = mitre_techniques

        # Detection event
        events.append({
            "id": f"evt-det-{threat_id}",
            "type": "detected",
            "timestamp": detected_at,
            "threatId": threat_id,
            "threatTitle": title,
            "severity": severity,
            "actor": "system",
            "account": acct,
            "details": f"MITRE: {technique}" if technique else None,
        })

        # Status-based events
        if status == "resolved":
            events.append({
                "id": f"evt-res-{threat_id}",
                "type": "resolved",
                "timestamp": updated_at or detected_at,
                "threatId": threat_id,
                "threatTitle": title,
                "severity": severity,
                "actor": t.get("assignee") or "system",
                "account": acct,
                "details": None,
            })
            # Compute resolution time
            det_dt = _parse_ts(detected_at)
            res_dt = _parse_ts(updated_at)
            if det_dt and res_dt and res_dt > det_dt:
                diff_hours = (res_dt - det_dt).total_seconds() / 3600
                resolution_times_hours.append(diff_hours)

        elif status == "investigating":
            events.append({
                "id": f"evt-inv-{threat_id}",
                "type": "investigating",
                "timestamp": updated_at or detected_at,
                "threatId": threat_id,
                "threatTitle": title,
                "severity": severity,
                "actor": t.get("assignee") or "soc-analyst",
                "account": acct,
                "details": None,
            })
        elif status in ("suppressed", "false-positive", "false_positive"):
            events.append({
                "id": f"evt-sup-{threat_id}",
                "type": "suppressed",
                "timestamp": updated_at or detected_at,
                "threatId": threat_id,
                "threatTitle": title,
                "severity": severity,
                "actor": t.get("assignee") or "system",
                "account": acct,
                "details": None,
            })

        # Assignment event
        assignee = t.get("assignee")
        if assignee:
            events.append({
                "id": f"evt-asg-{threat_id}",
                "type": "assigned",
                "timestamp": updated_at or detected_at,
                "threatId": threat_id,
                "threatTitle": title,
                "severity": severity,
                "actor": assignee,
                "account": acct,
                "details": f"Assigned to {assignee}",
            })

    # Add scan events from orchestration
    raw_scans = safe_get(scan_data, "scans", []) or []
    if isinstance(raw_scans, list):
        for s in raw_scans[:20]:
            scan_id = s.get("scan_run_id") or ""
            started = s.get("started_at") or s.get("created_at") or ""
            completed = s.get("completed_at") or ""
            status_scan = (s.get("status") or "").lower()
            if started:
                events.append({
                    "id": f"evt-scan-{scan_id}",
                    "type": "detected",
                    "timestamp": started,
                    "threatId": None,
                    "threatTitle": f"Scan {scan_id[:8]}..." if scan_id else "Security scan",
                    "severity": "low",
                    "actor": "system",
                    "account": s.get("account_id") or "",
                    "details": f"Status: {status_scan}" if status_scan else None,
                })

    # Sort by timestamp descending
    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)

    # KPI
    detected_count = sum(1 for e in events if e["type"] == "detected")
    resolved_count = sum(1 for e in events if e["type"] == "resolved")
    investigating_count = sum(1 for e in events if e["type"] == "investigating")

    # Compute average response time from actual resolution times
    if resolution_times_hours:
        avg_hours = sum(resolution_times_hours) / len(resolution_times_hours)
        if avg_hours < 1:
            avg_response_time = f"{round(avg_hours * 60)}m"
        elif avg_hours < 24:
            avg_response_time = f"{round(avg_hours, 1)}h"
        else:
            avg_response_time = f"{round(avg_hours / 24, 1)}d"
    else:
        avg_response_time = "—"

    return {
        "events": events[:limit],
        "kpi": {
            "totalEvents": len(events),
            "detected": detected_count,
            "resolved": resolved_count,
            "avgResponseTime": avg_response_time,
            "openInvestigations": investigating_count,
        },
    }
