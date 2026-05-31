"""CDR Enricher — correlates CDR findings to API gateway resources.

Queries cdr_findings for the past 24 h (or last scan window) for events
matching API gateway patterns:
  - execute-api calls with errorCode (authFailure, accessDenied, throttling)
  - Anomalous high-volume calls from a single actor (BOLA precursor)

Returns a list of api_security findings with finding_source='cdr' so the
storage layer can upsert them alongside config-based findings.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

logger = logging.getLogger("api_security.cdr_enricher")

_LOOKBACK_HOURS = 24

# CDR event names that indicate API gateway misuse
_AUTHFAIL_EVENTS = {
    "ExecuteApiInvalidPermission",
    "ExecuteApiAccessDenied",
    "ExecuteApiUnauthorized",
}
_THROTTLE_EVENTS = {"ExecuteApiThrottled", "ThrottlingException"}

# Minimum call volume to flag a single actor as anomalous (BOLA precursor)
_BOLA_CALL_THRESHOLD = 50


def _load_cdr_api_events(cdr_conn, tenant_id: str, lookback_hours: int) -> List[dict]:
    """Load CDR findings for API gateway event names within the lookback window."""
    since = datetime.now(tz=timezone.utc) - timedelta(hours=lookback_hours)
    sql = """
        SELECT
            id,
            tenant_id,
            event_name,
            event_source,
            actor_principal,
            resource_uid,
            resource_type,
            source_ip,
            error_code,
            error_message,
            event_time,
            raw_event
        FROM cdr_findings
        WHERE tenant_id = %s
          AND event_time >= %s
          AND (
                event_source ILIKE '%execute-api%'
             OR event_source ILIKE '%apigateway%'
             OR event_name ILIKE 'ExecuteApi%'
          )
        ORDER BY event_time DESC
        LIMIT 5000
    """
    with cdr_conn.cursor() as cur:
        cur.execute(sql, (tenant_id, since))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    return [dict(zip(cols, row)) for row in rows]


def enrich_with_cdr(
    api_findings: List[Dict[str, Any]],
    cdr_conn,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
) -> List[Dict[str, Any]]:
    """Correlate CDR events to existing API findings and emit new CDR-sourced findings.

    Returns the combined list of api_findings + newly generated CDR findings.
    If cdr_conn is None (CDR DB unavailable), returns api_findings unchanged.
    """
    if cdr_conn is None:
        logger.info("CDR enricher: no CDR connection, skipping enrichment")
        return api_findings

    try:
        cdr_events = _load_cdr_api_events(cdr_conn, tenant_id, _LOOKBACK_HOURS)
    except Exception as exc:
        logger.warning(f"CDR enricher: failed to load events: {exc}")
        return api_findings

    logger.info(f"CDR enricher: {len(cdr_events)} CDR API events in last {_LOOKBACK_HOURS}h")

    if not cdr_events:
        return api_findings

    new_findings: List[Dict[str, Any]] = list(api_findings)

    # --- Auth failure pattern ---
    auth_fail_by_resource: Dict[str, List[dict]] = {}
    for ev in cdr_events:
        event_name = (ev.get("event_name") or "").upper()
        error_code = (ev.get("error_code") or "").lower()
        if event_name in {e.upper() for e in _AUTHFAIL_EVENTS} or "unauthorized" in error_code or "accessdenied" in error_code:
            uid = ev.get("resource_uid") or ev.get("source_ip") or "unknown"
            auth_fail_by_resource.setdefault(uid, []).append(ev)

    for resource_uid, events in auth_fail_by_resource.items():
        actors = {e.get("actor_principal") for e in events if e.get("actor_principal")}
        sample = events[0]
        new_findings.append({
            "rule_id": "cdr.apigateway.repeated_auth_failures",
            "resource_uid": resource_uid,
            "resource_type": sample.get("resource_type") or "aws.apigateway.stage",
            "severity": "high",
            "title": "API Gateway: repeated authentication failures detected",
            "description": (
                f"{len(events)} authorization failures on this API endpoint in the last "
                f"{_LOOKBACK_HOURS} hours from {len(actors)} distinct actor(s). "
                "May indicate credential stuffing or misconfigured auth."
            ),
            "remediation": (
                "Review CloudTrail for the source IPs and actor principals. "
                "Enable WAF rules to block high-failure-rate IPs. "
                "Verify API authorizer configuration."
            ),
            "owasp_api_category": "API2",
            "finding_source": "cdr",
            "auth_type": "none",
            "has_waf": False,
            "has_rate_limit": False,
            "is_publicly_accessible": True,
            "api_gateway_id": resource_uid,
            "api_name": "",
            "api_stage": "",
            "evidence": {
                "eventCount": len(events),
                "actorCount": len(actors),
                "sampleEventName": sample.get("event_name"),
                "sampleErrorCode": sample.get("error_code"),
                "windowHours": _LOOKBACK_HOURS,
            },
        })

    # --- Throttle pattern ---
    throttle_by_resource: Dict[str, List[dict]] = {}
    for ev in cdr_events:
        event_name = (ev.get("event_name") or "").upper()
        error_code = (ev.get("error_code") or "").lower()
        if event_name in {e.upper() for e in _THROTTLE_EVENTS} or "throttl" in error_code:
            uid = ev.get("resource_uid") or "unknown"
            throttle_by_resource.setdefault(uid, []).append(ev)

    for resource_uid, events in throttle_by_resource.items():
        if len(events) < 10:
            continue
        sample = events[0]
        new_findings.append({
            "rule_id": "cdr.apigateway.excessive_throttling",
            "resource_uid": resource_uid,
            "resource_type": sample.get("resource_type") or "aws.apigateway.stage",
            "severity": "medium",
            "title": "API Gateway: excessive throttling events detected",
            "description": (
                f"{len(events)} throttling errors on this API in the last {_LOOKBACK_HOURS} hours. "
                "Consistent throttling may indicate a DoS attempt or misconfigured rate limits."
            ),
            "remediation": (
                "Review throttling limits and consider enabling usage plans with per-client "
                "quotas. Evaluate WAF rate-based rules."
            ),
            "owasp_api_category": "API4",
            "finding_source": "cdr",
            "auth_type": "none",
            "has_waf": False,
            "has_rate_limit": True,
            "is_publicly_accessible": True,
            "api_gateway_id": resource_uid,
            "api_name": "",
            "api_stage": "",
            "evidence": {
                "throttleEventCount": len(events),
                "windowHours": _LOOKBACK_HOURS,
            },
        })

    # --- BOLA precursor: single actor accessing many distinct resource IDs ---
    actor_resources: Dict[str, set] = {}
    for ev in cdr_events:
        actor = ev.get("actor_principal")
        uid = ev.get("resource_uid")
        if actor and uid:
            actor_resources.setdefault(actor, set()).add(uid)

    for actor, resources in actor_resources.items():
        if len(resources) >= _BOLA_CALL_THRESHOLD:
            new_findings.append({
                "rule_id": "cdr.apigateway.bola_precursor",
                "resource_uid": f"actor:{actor}",
                "resource_type": "aws.apigateway.stage",
                "severity": "high",
                "title": "API Gateway: single actor accessing excessive distinct resources (BOLA precursor)",
                "description": (
                    f"Actor '{actor}' accessed {len(resources)} distinct API resource identifiers "
                    f"in the last {_LOOKBACK_HOURS} hours. This pattern is consistent with "
                    "Broken Object Level Authorization (OWASP API1) enumeration."
                ),
                "remediation": (
                    "Review access logs for this actor. Implement object-level authorization checks "
                    "at the application layer (not just at the gateway). Consider rate-limiting "
                    "per-user resource access."
                ),
                "owasp_api_category": "API1",
                "finding_source": "cdr",
                "auth_type": "none",
                "has_waf": False,
                "has_rate_limit": False,
                "is_publicly_accessible": True,
                "api_gateway_id": "",
                "api_name": "",
                "api_stage": "",
                "evidence": {
                    "actorPrincipal": actor,
                    "distinctResourceCount": len(resources),
                    "threshold": _BOLA_CALL_THRESHOLD,
                    "windowHours": _LOOKBACK_HOURS,
                },
            })

    cdr_count = len(new_findings) - len(api_findings)
    logger.info(f"CDR enricher complete: added {cdr_count} CDR-sourced findings")
    return new_findings
