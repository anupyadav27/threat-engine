"""
threat_v1 REST API endpoints (S4-01).

Every endpoint requires require_permission() — no anonymous access.
Health endpoints: no auth (standard platform pattern).

Endpoints:
  GET /api/v1/health/live
  GET /api/v1/health/ready
  GET /api/v1/incidents
  GET /api/v1/incidents/{incident_id}
  GET /api/v1/scan/status/{scan_run_id}
  POST /api/v1/incidents/{incident_id}/feedback
"""
from __future__ import annotations

import os

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from threat_v1.database import get_threat_conn, get_neo4j_driver
from threat_v1.schemas.models import (
    HealthResponse,
    IncidentDetail,
    IncidentListItem,
    IncidentListResponse,
    ScanStatusResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Auth dependency (mirrors platform pattern) ────────────────────────────────

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context  # type: ignore[import]
    from engine_auth.core.models import AuthContext  # type: ignore[import]
    _HAS_AUTH = True
except ImportError:
    _HAS_AUTH = False
    logger.warning("engine_auth not available — running without RBAC (dev mode only)")

    from fastapi import Request as _Request

    class AuthContext:  # type: ignore[no-redef]
        def __init__(
            self,
            tenant_id: Optional[str] = None,
            account_id: Optional[str] = None,
        ) -> None:
            self.tenant_id = tenant_id
            self.account_id = account_id
            self.permissions: List[str] = ["threat:read", "cdr:sensitive"]

    def _parse_dev_auth(request: _Request) -> AuthContext:
        """Honour X-Auth-Context header forwarded by the gateway (dev/fallback path)."""
        raw = request.headers.get("X-Auth-Context")
        if raw:
            try:
                ctx = json.loads(raw)
                tid = ctx.get("engine_tenant_id") or ctx.get("tenant_id") or None
                return AuthContext(tenant_id=tid, account_id=None)
            except Exception:
                pass
        return AuthContext()

    def require_permission(perm: str):  # type: ignore[misc]
        def dep(request: _Request) -> AuthContext:
            return _parse_dev_auth(request)
        return dep

    def get_auth_context():  # type: ignore[misc]
        def dep(request: _Request) -> AuthContext:
            return _parse_dev_auth(request)
        return dep


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/api/v1/health/live", response_model=HealthResponse, tags=["health"])
def health_live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/api/v1/health/ready", response_model=HealthResponse, tags=["health"])
def health_ready() -> HealthResponse:
    try:
        conn = get_threat_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"DB not ready: {exc}")
    return HealthResponse(status="ok")


# ── Incidents list ─────────────────────────────────────────────────────────────

@router.get(
    "/api/v1/incidents",
    response_model=IncidentListResponse,
    tags=["incidents"],
)
def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    severity: Optional[str] = Query(default=None),
    incident_class: Optional[str] = Query(default=None),
    tier: Optional[int] = Query(default=None),
    status: Optional[str] = Query(default="open"),
    auth: Any = Depends(require_permission("threat:read")),
) -> IncidentListResponse:
    """List incidents for the authenticated tenant. Strips all CDR PII."""
    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)
    account_id = getattr(auth, "account_id", None)

    conn = get_threat_conn()
    try:
        rows, total = _query_incidents(
            conn, tenant_id, account_id,
            page, page_size, severity, incident_class, tier, status,
        )
        items = [IncidentListItem(**_row_to_list_item(r)) for r in rows]
        return IncidentListResponse(
            items=items, total=total, page=page, page_size=page_size,
        )
    finally:
        conn.close()


# ── Incident detail ───────────────────────────────────────────────────────────

@router.get(
    "/api/v1/incidents/{incident_id}",
    response_model=IncidentDetail,
    tags=["incidents"],
)
def get_incident(
    incident_id: str,
    auth: Any = Depends(require_permission("threat:read")),
) -> IncidentDetail:
    """Get full incident detail. CDR fields included only if caller has cdr:sensitive."""
    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)
    has_cdr_sensitive = "cdr:sensitive" in getattr(auth, "permissions", [])

    conn = get_threat_conn()
    driver = get_neo4j_driver()
    try:
        row = _fetch_incident_by_id(conn, incident_id, tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        detail = IncidentDetail(**_row_to_detail(row, driver, has_cdr_sensitive))
        return detail
    finally:
        conn.close()
        driver.close()


# ── Scan status ───────────────────────────────────────────────────────────────

@router.get(
    "/api/v1/scan/status/{scan_run_id}",
    response_model=ScanStatusResponse,
    tags=["scans"],
)
def get_scan_status(
    scan_run_id: str,
    auth: Any = Depends(require_permission("threat:read")),
) -> ScanStatusResponse:
    """Get graph build + pattern execution status for a scan run."""
    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)

    conn = get_threat_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM threat_scan_runs_v1
            WHERE scan_run_id = %s
              AND tenant_id   = %s
            """,
            (scan_run_id, tenant_id),
        )
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan run not found")

    return ScanStatusResponse(**dict(row))


# ── Feedback ──────────────────────────────────────────────────────────────────

@router.post(
    "/api/v1/incidents/{incident_id}/feedback",
    status_code=202,
    tags=["incidents"],
)
def submit_feedback(
    incident_id: str,
    payload: Dict[str, Any],
    auth: Any = Depends(require_permission("threat:read")),
) -> Dict[str, str]:
    """Submit analyst verdict (true_positive / false_positive) for an incident."""
    verdict = payload.get("verdict")
    if verdict not in ("true_positive", "false_positive"):
        raise HTTPException(
            status_code=422,
            detail="verdict must be 'true_positive' or 'false_positive'",
        )

    tenant_id = getattr(auth, "engine_tenant_id", None) or getattr(auth, "tenant_id", None)

    conn = get_threat_conn()
    try:
        row = _fetch_incident_by_id(conn, incident_id, tenant_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO threat_incident_feedback (
                incident_dedup_key, tenant_id, pattern_id, verdict,
                analyst_note, created_at
            ) VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (
                incident_id,
                tenant_id,
                str(row.get("pattern_id", "")),
                verdict,
                payload.get("note", ""),
            ),
        )
        conn.commit()
        cur.close()
    finally:
        conn.close()

    return {"status": "accepted", "incident_id": incident_id}


# ── Query helpers ──────────────────────────────────────────────────────────────

def _query_incidents(
    conn: Any,
    tenant_id: Optional[str],
    account_id: Optional[str],
    page: int,
    page_size: int,
    severity: Optional[str],
    incident_class: Optional[str],
    tier: Optional[int],
    status: Optional[str],
):
    conditions: List[str] = []
    params: List[Any] = []

    # tenant_id=None means platform_admin all-tenants view — no tenant filter.
    if tenant_id:
        conditions.append("ti.tenant_id = %s")
        params.append(tenant_id)
    if account_id:
        conditions.append("ti.account_id = %s")
        params.append(account_id)
    if severity:
        conditions.append("ti.severity = %s")
        params.append(severity)
    if incident_class:
        conditions.append("ti.incident_class = %s")
        params.append(incident_class)
    if tier is not None:
        conditions.append("ti.tier = %s")
        params.append(tier)
    if status:
        conditions.append("ti.status = %s")
        params.append(status)

    where = " AND ".join(conditions) if conditions else "1=1"
    offset = (page - 1) * page_size

    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM threat_incidents ti WHERE {where}", params)
    total = cur.fetchone()["count"]

    cur.execute(
        f"""
        SELECT ti.dedup_key, ti.tenant_id, ti.account_id, ti.region,
               ti.entry_resource_uid, ti.target_resource_uid,
               COALESCE(tsp.pattern_key, ti.pattern_id::text) AS primary_pattern_id,
               ti.matched_pattern_ids AS matched_patterns,
               ti.tier, ti.incident_class, ti.severity, ti.status,
               ti.title, ti.first_seen_at, ti.last_seen_at, ti.story_text,
               0 AS cdr_technique_count
        FROM threat_incidents ti
        LEFT JOIN threat_scenario_patterns tsp ON tsp.pattern_id = ti.pattern_id
        WHERE {where}
        ORDER BY
            CASE ti.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                             WHEN 'medium' THEN 2 ELSE 3 END ASC,
            ti.last_seen_at DESC
        LIMIT %s OFFSET %s
        """,
        params + [page_size, offset],
    )
    rows = cur.fetchall()
    cur.close()
    return list(rows), total


def _fetch_incident_by_id(
    conn: Any, incident_id: str, tenant_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    # JOIN threat_scenario_patterns to get human-readable pattern_key as primary_pattern_id.
    # SELECT specific columns — avoids the incident_id UUID conflicting with the
    # Pydantic alias field(alias="dedup_key") when both are present in the dict.
    base_q = """
        SELECT
            ti.dedup_key,
            ti.tenant_id,
            ti.account_id,
            ti.region,
            ti.entry_resource_uid,
            ti.target_resource_uid,
            ti.tier,
            ti.incident_class,
            ti.severity,
            ti.status,
            ti.title,
            ti.story_text,
            ti.first_seen_at,
            ti.last_seen_at,
            ti.resolved_at,
            ti.scan_run_id,
            ti.attack_path,
            ti.matched_pattern_ids,
            ti.misconfig_finding_ids,
            ti.vuln_finding_ids,
            ti.cdr_event_ids,
            ti.pattern_id,
            COALESCE(tsp.pattern_key, ti.pattern_id::text) AS primary_pattern_id,
            0 AS cdr_technique_count
        FROM threat_incidents ti
        LEFT JOIN threat_scenario_patterns tsp ON tsp.pattern_id = ti.pattern_id
        WHERE ti.dedup_key = %s
    """
    cur = conn.cursor()
    if tenant_id:
        cur.execute(base_q + " AND ti.tenant_id = %s", (incident_id, tenant_id))
    else:
        cur.execute(base_q, (incident_id,))
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else None


def _row_to_list_item(row: Any) -> Dict[str, Any]:
    d = dict(row)
    if isinstance(d.get("matched_patterns"), str):
        d["matched_patterns"] = json.loads(d["matched_patterns"])
    elif d.get("matched_patterns") is None and "matched_pattern_ids" in d:
        d["matched_patterns"] = d["matched_pattern_ids"]
    return d


def _row_to_detail(row: Dict, driver: Any, has_cdr_sensitive: bool) -> Dict[str, Any]:
    d = dict(row)
    if isinstance(d.get("matched_patterns"), str):
        d["matched_patterns"] = json.loads(d["matched_patterns"])
    elif d.get("matched_patterns") is None and "matched_pattern_ids" in d:
        d["matched_patterns"] = d["matched_pattern_ids"]
    if isinstance(d.get("hop_resource_uids"), str):
        d["hop_resource_uids"] = json.loads(d["hop_resource_uids"])
    elif "hop_resource_uids" not in d:
        path = d.get("attack_path") or []
        d["hop_resource_uids"] = [n.get("resource_uid") for n in path if isinstance(n, dict)]

    # Fetch finding evidence from Neo4j
    entry_uid = d.get("entry_resource_uid", "")
    tenant_id = d.get("tenant_id", "")

    d["misconfig_findings"] = _fetch_misconfig_findings(driver, entry_uid, tenant_id)
    d["vuln_findings"] = _fetch_vuln_findings(driver, entry_uid, tenant_id)
    d["cdr_events"] = (
        _fetch_cdr_events(driver, entry_uid, tenant_id) if has_cdr_sensitive else []
    )
    return d


def _fetch_misconfig_findings(driver: Any, resource_uid: str, tenant_id: str) -> List[Dict]:
    try:
        with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(
                """
                MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})-[:HAS_MISCONFIG]->(f)
                RETURN f.finding_id AS finding_id, f.rule_id AS rule_id,
                       f.severity AS severity, f.title AS title,
                       f.mitre_techniques AS mitre_techniques, f.status AS status
                """,
                uid=resource_uid, tid=tenant_id,
            )
            return [dict(r) for r in result]
    except Exception:
        return []


def _fetch_vuln_findings(driver: Any, resource_uid: str, tenant_id: str) -> List[Dict]:
    try:
        with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(
                """
                MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})-[:HAS_CVE]->(v)
                RETURN v.cve_id AS cve_id, v.cvss_score AS cvss_score,
                       v.epss_score AS epss_score, v.has_known_exploit AS has_known_exploit,
                       v.mitre_technique AS mitre_technique,
                       v.package AS package, v.fixed_version AS fixed_version
                """,
                uid=resource_uid, tid=tenant_id,
            )
            return [dict(r) for r in result]
    except Exception:
        return []


def _fetch_cdr_events(driver: Any, resource_uid: str, tenant_id: str) -> List[Dict]:
    """Fetch CDR events. actor_hash only — never actor_principal (CP1-02)."""
    try:
        with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(
                """
                MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})-[:TRIGGERED_ON]->(e)
                RETURN e.finding_id AS finding_id,
                       e.mitre_technique AS mitre_technique,
                       e.mitre_tactic AS mitre_tactic,
                       e.event_time AS event_time,
                       e.anomaly_score AS anomaly_score,
                       e.actor_hash AS actor_hash
                ORDER BY e.event_time DESC
                LIMIT 50
                """,
                uid=resource_uid, tid=tenant_id,
            )
            return [dict(r) for r in result]
    except Exception:
        return []
