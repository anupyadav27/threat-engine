"""
Threat Engine — Unified UI Data Endpoint

GET /api/v1/threat/ui-data

Returns ALL threat data the UI needs in a single call.
Source: threat_findings (enriched check failures + MITRE mapping).
Consumed by: threats BFF, misconfig BFF, dashboard BFF.
"""

import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _get_conn():
    """Create a new psycopg2 connection to the threat DB."""
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        dbname=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "threat_user"),
        password=os.getenv("THREAT_DB_PASSWORD", "threat_password"),
        connect_timeout=5,
    )


def _safe_json(val):
    """Ensure JSONB values are dicts/lists (psycopg2 auto-deserialises)."""
    if val is None:
        return {}
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return {}
    return {}


_SEV_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

@router.get("/api/v1/threat/ui-data")
async def get_threat_ui_data(
    tenant_id: str = Query(..., description="Tenant identifier"),
    scan_run_id: Optional[str] = Query(None, description="Scan run ID (default: latest)"),
    limit: int = Query(200, ge=1, le=1000, description="Max findings to return"),
    offset: int = Query(0, ge=0),
    days: int = Query(30, ge=1, le=365, description="Trend lookback days"),
    severity: Optional[str] = Query(None, description="Filter findings by severity"),
    account_id: Optional[str] = Query(None, description="Filter findings by account"),
    region: Optional[str] = Query(None, description="Filter findings by region"),
):
    """
    Unified UI data endpoint — returns all threat data for the UI in one call.

    Serves: threats page, misconfig page, dashboard (threat section).
    """
    start = time.time()
    conn = None

    try:
        conn = _get_conn()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        # ------------------------------------------------------------------ #
        # 1. Resolve threat_scan_id (latest if not provided)
        # ------------------------------------------------------------------ #
        threat_scan_id = _resolve_scan_id(conn, tenant_id, scan_run_id)
        if not threat_scan_id:
            return _empty_response()

        base_where = "tenant_id = %s AND threat_scan_id = %s"
        base_params: list = [tenant_id, threat_scan_id]

        # Build filter WHERE (for paginated findings only)
        f_where, f_params = _build_filter_clause(
            base_where, base_params, severity, account_id, region
        )

        # ------------------------------------------------------------------ #
        # 2. Summary (unfiltered — KPI always reflects full scan)
        # ------------------------------------------------------------------ #
        summary = _query_summary(conn, base_where, base_params)

        # ------------------------------------------------------------------ #
        # 3. Aggregations: by_service, by_account, by_region
        # ------------------------------------------------------------------ #
        summary["by_service"] = _query_by_service(conn, base_where, base_params)
        summary["by_account"] = _query_by_account(conn, base_where, base_params)
        summary["by_region"] = _query_by_region(conn, base_where, base_params)

        # ------------------------------------------------------------------ #
        # 4. SLA / MTTR stats
        # ------------------------------------------------------------------ #
        sla = _query_sla_stats(conn, base_where, base_params)
        summary["mean_time_to_remediate_hours"] = sla["mttr_hours"]
        summary["sla_compliance_pct"] = sla["sla_pct"]
        summary["auto_remediable"] = _query_auto_remediable(conn, base_where, base_params)

        # ------------------------------------------------------------------ #
        # 5. Paginated findings list (filters applied)
        # ------------------------------------------------------------------ #
        findings, total_filtered = _query_findings(conn, f_where, f_params, limit, offset)

        # ------------------------------------------------------------------ #
        # 6. MITRE matrix
        # ------------------------------------------------------------------ #
        mitre_matrix = _query_mitre_matrix(conn, base_where, base_params)

        # ------------------------------------------------------------------ #
        # 7. Trend
        # ------------------------------------------------------------------ #
        trend = _query_trend(conn, tenant_id, days)

        # ------------------------------------------------------------------ #
        # 8. Threat intelligence
        # ------------------------------------------------------------------ #
        threat_intel = _query_intel(conn, tenant_id)

        # ------------------------------------------------------------------ #
        # 9. Remediation queue
        # ------------------------------------------------------------------ #
        remediation_queue = _query_remediation_queue(conn, base_where, base_params)

        # ------------------------------------------------------------------ #
        # 10. Detections (from threat_detections table)
        # ------------------------------------------------------------------ #
        detections = _query_detections(conn, tenant_id)
        detections_summary = _detections_summary(detections)

        # ------------------------------------------------------------------ #
        # 11. Analysis (from threat_analysis table — confirmed attack chains)
        # ------------------------------------------------------------------ #
        analysis = _query_analysis(conn, tenant_id)
        analysis_summary = _build_analysis_summary(conn, tenant_id)

        # Release DB connection before graph queries
        conn.close()
        conn = None

        # ------------------------------------------------------------------ #
        # 10. Graph queries (Neo4j — always available in production)
        # ------------------------------------------------------------------ #
        graph_data = _query_graph_data(tenant_id)
        attack_paths = graph_data["attack_paths"]
        toxic_combinations = graph_data["toxic_combinations"]
        internet_exposed = graph_data["internet_exposed"]

        duration_ms = (time.time() - start) * 1000
        logger.info(
            "UI data served",
            extra={"extra_fields": {
                "duration_ms": round(duration_ms, 1),
                "total_findings": summary["total"],
            }},
        )

        return {
            "summary": summary,
            "threats": findings,
            "total_threats": total_filtered,
            "trend": trend,
            "mitre_matrix": mitre_matrix,
            "attack_paths": attack_paths,
            "toxic_combinations": toxic_combinations,
            "internet_exposed": internet_exposed,
            "threat_intel": threat_intel,
            "remediation_queue": remediation_queue,
            "detections": detections,
            "detections_summary": detections_summary,
            "analysis": analysis,
            "analysis_summary": analysis_summary,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ui-data endpoint failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# =========================================================================== #
# Private query helpers
# =========================================================================== #

def _empty_response() -> dict:
    return {
        "summary": {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "by_category": {}, "by_service": [], "by_account": [], "by_region": [],
            "mean_time_to_remediate_hours": 0, "sla_compliance_pct": 100,
            "auto_remediable": 0,
        },
        "threats": [],
        "total_threats": 0,
        "trend": [],
        "mitre_matrix": [],
        "attack_paths": [],
        "toxic_combinations": [],
        "internet_exposed": {"total": 0, "resources": []},
        "threat_intel": [],
        "remediation_queue": [],
        "detections": [],
        "detections_summary": {"active_detections": 0, "detection_types": {}},
        "analysis": [],
        "analysis_summary": {"total_analyses": 0, "by_verdict": {}, "by_analysis_type": {}, "avg_risk_score": 0},
    }


def _resolve_scan_id(conn, tenant_id: str, scan_run_id: Optional[str]) -> Optional[str]:
    with conn.cursor() as cur:
        if scan_run_id and scan_run_id != "latest":
            cur.execute(
                "SELECT threat_scan_id FROM threat_report "
                "WHERE tenant_id = %s AND scan_run_id = %s "
                "ORDER BY created_at DESC LIMIT 1",
                (tenant_id, scan_run_id),
            )
        else:
            cur.execute(
                "SELECT threat_scan_id FROM threat_report "
                "WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1",
                (tenant_id,),
            )
        row = cur.fetchone()
        return row[0] if row else None


def _build_filter_clause(base_where, base_params, severity, account_id, region):
    f_where = base_where
    f_params = list(base_params)
    if severity:
        f_where += " AND severity = %s"
        f_params.append(severity)
    if account_id:
        f_where += " AND account_id = %s"
        f_params.append(account_id)
    if region:
        f_where += " AND region = %s"
        f_params.append(region)
    return f_where, f_params


# -- summary ----------------------------------------------------------------

def _query_summary(conn, where: str, params: list) -> dict:
    summary: Dict[str, Any] = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "resolved_count": 0, "by_category": {},
    }
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT severity, threat_category, status, COUNT(*) AS cnt "
            f"FROM threat_findings WHERE {where} GROUP BY severity, threat_category, status",
            params,
        )
        for row in cur.fetchall():
            sev = (row["severity"] or "low").lower()
            cat = row["threat_category"] or "uncategorized"
            cnt = row["cnt"]
            summary[sev] = summary.get(sev, 0) + cnt
            summary["total"] += cnt
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + cnt
            if (row["status"] or "").lower() == "resolved":
                summary["resolved_count"] += cnt
    return summary


# -- by service -------------------------------------------------------------

def _query_by_service(conn, where: str, params: list) -> List[dict]:
    svc_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"service": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT COALESCE(finding_data->>'finding_key', 'unknown') AS service, "
            f"severity, COUNT(*) AS cnt "
            f"FROM threat_findings WHERE {where} GROUP BY 1, 2",
            params,
        )
        for row in cur.fetchall():
            svc = row["service"]
            sev = (row["severity"] or "low").lower()
            svc_map[svc]["service"] = svc
            svc_map[svc]["count"] += row["cnt"]
            svc_map[svc][sev] = svc_map[svc].get(sev, 0) + row["cnt"]
    return sorted(svc_map.values(), key=lambda x: x["count"], reverse=True)[:30]


# -- by account -------------------------------------------------------------

def _query_by_account(conn, where: str, params: list) -> List[dict]:
    acct_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"account_id": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT account_id, severity, COUNT(*) AS cnt "
            f"FROM threat_findings WHERE {where} GROUP BY account_id, severity",
            params,
        )
        for row in cur.fetchall():
            acct = row["account_id"] or "unknown"
            sev = (row["severity"] or "low").lower()
            acct_map[acct]["account_id"] = acct
            acct_map[acct]["count"] += row["cnt"]
            acct_map[acct][sev] = acct_map[acct].get(sev, 0) + row["cnt"]
    return sorted(acct_map.values(), key=lambda x: x["count"], reverse=True)


# -- by region --------------------------------------------------------------

def _query_by_region(conn, where: str, params: list) -> List[dict]:
    """Aggregate threat findings by region with severity breakdown."""
    region_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"region": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT region, severity, COUNT(*) AS cnt "
            f"FROM threat_findings WHERE {where} GROUP BY region, severity",
            params,
        )
        for row in cur.fetchall():
            rgn = row["region"] or "unknown"
            sev = (row["severity"] or "low").lower()
            region_map[rgn]["region"] = rgn
            region_map[rgn]["count"] += row["cnt"]
            region_map[rgn][sev] = region_map[rgn].get(sev, 0) + row["cnt"]
    return sorted(region_map.values(), key=lambda x: x["count"], reverse=True)


# -- SLA / MTTR -------------------------------------------------------------

def _query_sla_stats(conn, where: str, params: list) -> dict:
    result = {"mttr_hours": 0.0, "sla_pct": 100.0}
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # MTTR from resolved findings
            cur.execute(
                f"SELECT AVG(EXTRACT(EPOCH FROM (last_seen_at - first_seen_at))) / 3600 AS mttr "
                f"FROM threat_findings "
                f"WHERE {where} AND status = 'resolved' "
                f"AND first_seen_at IS NOT NULL AND last_seen_at IS NOT NULL",
                params,
            )
            row = cur.fetchone()
            if row and row.get("mttr"):
                result["mttr_hours"] = round(float(row["mttr"]), 1)

            # SLA compliance (using standard SLA thresholds)
            cur.execute(
                f"SELECT "
                f"  COUNT(*) FILTER (WHERE "
                f"    (severity='critical' AND EXTRACT(EPOCH FROM (NOW()-COALESCE(first_seen_at,created_at)))/86400 <= 7) "
                f"    OR (severity='high' AND EXTRACT(EPOCH FROM (NOW()-COALESCE(first_seen_at,created_at)))/86400 <= 14) "
                f"    OR (severity='medium' AND EXTRACT(EPOCH FROM (NOW()-COALESCE(first_seen_at,created_at)))/86400 <= 30) "
                f"    OR (severity='low' AND EXTRACT(EPOCH FROM (NOW()-COALESCE(first_seen_at,created_at)))/86400 <= 90) "
                f"  ) AS within_sla, "
                f"  COUNT(*) AS total "
                f"FROM threat_findings WHERE {where} AND status != 'resolved'",
                params,
            )
            row = cur.fetchone()
            if row and row["total"] and row["total"] > 0:
                result["sla_pct"] = round(100.0 * float(row["within_sla"]) / float(row["total"]), 1)
    except Exception as e:
        logger.warning(f"SLA stats query failed: {e}")
    return result


def _query_auto_remediable(conn, where: str, params: list) -> int:
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM threat_findings "
                f"WHERE {where} AND (finding_data->>'auto_remediable')::boolean = true",
                params,
            )
            return cur.fetchone()[0]
    except Exception:
        return 0


# -- findings ---------------------------------------------------------------

def _query_findings(conn, where: str, params: list, limit: int, offset: int):
    total = 0
    findings: List[dict] = []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"SELECT COUNT(*) AS cnt FROM threat_findings WHERE {where}", params)
        total = cur.fetchone()["cnt"]

        cur.execute(
            f"SELECT "
            f"  finding_id, rule_id, threat_category, severity, status, "
            f"  resource_type, resource_id, resource_arn, resource_uid, "
            f"  account_id, region, "
            f"  mitre_tactics, mitre_techniques, "
            f"  evidence, finding_data, "
            f"  first_seen_at, last_seen_at, created_at "
            f"FROM threat_findings WHERE {where} "
            f"ORDER BY "
            f"  CASE severity "
            f"    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            f"    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 "
            f"  END, created_at DESC "
            f"LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        for row in cur.fetchall():
            fd = _safe_json(row.get("finding_data"))
            findings.append({
                "finding_id": row["finding_id"],
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "status": row["status"],
                "threat_category": row["threat_category"],
                "resource_uid": row["resource_uid"],
                "resource_arn": row["resource_arn"],
                "resource_type": row["resource_type"],
                "account_id": row["account_id"],
                "region": row["region"],
                "service": fd.get("finding_key", ""),
                "title": fd.get("title", ""),
                "description": fd.get("description", ""),
                "remediation": fd.get("remediation", ""),
                "risk_score": fd.get("risk_score", 50),
                "mitre_techniques": _safe_json(row.get("mitre_techniques")) or [],
                "mitre_tactics": _safe_json(row.get("mitre_tactics")) or [],
                "evidence": _safe_json(row.get("evidence")),
                "first_seen_at": _ts(row.get("first_seen_at")),
                "last_seen_at": _ts(row.get("last_seen_at")),
            })
    return findings, total


def _ts(val) -> Optional[str]:
    return str(val) if val else None


# -- MITRE matrix -----------------------------------------------------------

def _query_mitre_matrix(conn, where: str, params: list) -> List[dict]:
    matrix: List[dict] = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"WITH technique_counts AS ( "
                f"  SELECT "
                f"    CASE "
                f"      WHEN jsonb_typeof(elem) = 'object' THEN elem->>'id' "
                f"      WHEN jsonb_typeof(elem) = 'string' THEN elem #>> '{{}}' "
                f"      ELSE NULL "
                f"    END AS technique_id, "
                f"    COUNT(*) AS finding_count "
                f"  FROM threat_findings, "
                f"       jsonb_array_elements(COALESCE(mitre_techniques, '[]'::jsonb)) AS elem "
                f"  WHERE {where} "
                f"    AND mitre_techniques IS NOT NULL "
                f"    AND mitre_techniques != '[]'::jsonb "
                f"  GROUP BY 1 "
                f") "
                f"SELECT tc.technique_id, tc.finding_count, "
                f"       mr.technique_name, mr.tactics, mr.severity_base "
                f"FROM technique_counts tc "
                f"LEFT JOIN mitre_technique_reference mr ON tc.technique_id = mr.technique_id "
                f"WHERE tc.technique_id IS NOT NULL "
                f"ORDER BY tc.finding_count DESC",
                params,
            )
            for row in cur.fetchall():
                tactics = _safe_json(row.get("tactics"))
                if isinstance(tactics, str):
                    tactics = [tactics]
                matrix.append({
                    "technique_id": row["technique_id"],
                    "technique_name": row.get("technique_name") or row["technique_id"],
                    "tactics": tactics if isinstance(tactics, list) else [],
                    "count": row["finding_count"],
                    "severity_base": row.get("severity_base") or "medium",
                })
    except Exception as e:
        logger.warning(f"MITRE matrix query failed: {e}")
    return matrix


# -- trend ------------------------------------------------------------------

def _query_trend(conn, tenant_id: str, days: int) -> List[dict]:
    trend: List[dict] = []
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        date_map: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"date": "", "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT DATE(created_at) AS d, severity, COUNT(*) AS cnt "
                "FROM threat_findings "
                "WHERE tenant_id = %s AND created_at >= %s "
                "GROUP BY 1, 2 ORDER BY 1",
                (tenant_id, cutoff),
            )
            for row in cur.fetchall():
                d = str(row["d"])
                sev = (row["severity"] or "low").lower()
                date_map[d]["date"] = d
                date_map[d]["total"] += row["cnt"]
                date_map[d][sev] = date_map[d].get(sev, 0) + row["cnt"]
        trend = [date_map[k] for k in sorted(date_map.keys())]
    except Exception as e:
        logger.warning(f"Trend query failed: {e}")
    return trend


# -- intel ------------------------------------------------------------------

def _query_intel(conn, tenant_id: str) -> List[dict]:
    intel: List[dict] = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT intel_id, source, intel_type, severity, confidence, "
                "       threat_data, indicators, ttps, tags, "
                "       created_at, expires_at "
                "FROM threat_intelligence "
                "WHERE tenant_id = %s AND is_active = true "
                "ORDER BY created_at DESC LIMIT 50",
                (tenant_id,),
            )
            for row in cur.fetchall():
                item = dict(row)
                for k in ("created_at", "expires_at"):
                    if item.get(k):
                        item[k] = str(item[k])
                if item.get("intel_id"):
                    item["intel_id"] = str(item["intel_id"])
                intel.append(item)
    except Exception as e:
        logger.warning(f"Intel query failed: {e}")
    return intel


# -- remediation queue ------------------------------------------------------

def _query_remediation_queue(conn, where: str, params: list) -> List[dict]:
    queue: List[dict] = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT finding_id, rule_id, severity, status, "
                f"  resource_uid, account_id, region, finding_data, "
                f"  first_seen_at, created_at, "
                f"  EXTRACT(EPOCH FROM (NOW() - COALESCE(first_seen_at, created_at))) / 86400 AS age_days "
                f"FROM threat_findings "
                f"WHERE {where} AND severity IN ('critical', 'high') AND status != 'resolved' "
                f"ORDER BY "
                f"  CASE severity WHEN 'critical' THEN 1 ELSE 2 END, "
                f"  first_seen_at ASC NULLS LAST "
                f"LIMIT 50",
                params,
            )
            for row in cur.fetchall():
                fd = _safe_json(row.get("finding_data"))
                age = float(row.get("age_days") or 0)
                sla_days = 7 if row["severity"] == "critical" else 14
                queue.append({
                    "finding_id": row["finding_id"],
                    "rule_id": row["rule_id"],
                    "severity": row["severity"],
                    "title": fd.get("title", ""),
                    "resource_uid": row["resource_uid"],
                    "account_id": row["account_id"],
                    "region": row["region"],
                    "age_days": round(age, 1),
                    "sla_target_days": sla_days,
                    "sla_status": "breached" if age > sla_days else "within",
                })
    except Exception as e:
        logger.warning(f"Remediation queue query failed: {e}")
    return queue


# -- detections -------------------------------------------------------------

def _query_detections(conn, tenant_id: str) -> List[dict]:
    """Query threat_detections for recent detection events."""
    detections: List[dict] = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT detection_id, detection_type, rule_name, severity, confidence, "
                "       status, threat_category, mitre_tactics, mitre_techniques, "
                "       indicators, detection_timestamp "
                "FROM threat_detections "
                "WHERE tenant_id = %s "
                "ORDER BY detection_timestamp DESC "
                "LIMIT 50",
                (tenant_id,),
            )
            for row in cur.fetchall():
                item = {
                    "detection_id": str(row["detection_id"]) if row.get("detection_id") else None,
                    "detection_type": row.get("detection_type"),
                    "rule_name": row.get("rule_name"),
                    "severity": row.get("severity"),
                    "confidence": float(row["confidence"]) if row.get("confidence") is not None else None,
                    "status": row.get("status"),
                    "threat_category": row.get("threat_category"),
                    "mitre_tactics": _safe_json(row.get("mitre_tactics")) or [],
                    "mitre_techniques": _safe_json(row.get("mitre_techniques")) or [],
                    "indicators": _safe_json(row.get("indicators")),
                    "detection_timestamp": _ts(row.get("detection_timestamp")),
                }
                detections.append(item)
    except Exception as e:
        logger.warning(f"Detections query failed (table may not exist): {e}")
    return detections


def _detections_summary(detections: List[dict]) -> dict:
    """Compute summary counts from already-fetched detections list.

    Returns:
        dict with ``active_detections`` (int) and ``detection_types`` (dict).
    """
    active = 0
    type_counts: Dict[str, int] = defaultdict(int)
    for d in detections:
        if (d.get("status") or "").lower() == "open":
            active += 1
        dt = d.get("detection_type") or "unknown"
        type_counts[dt] += 1
    return {
        "active_detections": active,
        "detection_types": dict(type_counts),
    }


# -- analysis (DB-side attack chains) --------------------------------------

def _query_analysis(conn, tenant_id: str) -> List[dict]:
    """Query threat_analysis for confirmed attack chains and analysis results."""
    analysis: List[dict] = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT analysis_id, analysis_type, analyzer, risk_score, verdict, "
                "       analysis_results, recommendations, attack_chain "
                "FROM threat_analysis "
                "WHERE tenant_id = %s AND verdict = 'confirmed' "
                "ORDER BY risk_score DESC "
                "LIMIT 20",
                (tenant_id,),
            )
            for row in cur.fetchall():
                item = {
                    "analysis_id": str(row["analysis_id"]) if row.get("analysis_id") else None,
                    "analysis_type": row.get("analysis_type"),
                    "analyzer": row.get("analyzer"),
                    "risk_score": row.get("risk_score"),
                    "verdict": row.get("verdict"),
                    "analysis_results": _safe_json(row.get("analysis_results")),
                    "recommendations": _safe_json(row.get("recommendations")),
                    "attack_chain": _safe_json(row.get("attack_chain")),
                }
                analysis.append(item)
    except Exception as e:
        logger.warning(f"Analysis query failed (table may not exist): {e}")
    return analysis


def _build_analysis_summary(conn, tenant_id: str) -> dict:
    """Build aggregated summary from threat_analysis table.

    Returns:
        dict with total_analyses, by_verdict counts, by_analysis_type counts,
        and avg_risk_score.
    """
    summary: Dict[str, Any] = {
        "total_analyses": 0,
        "by_verdict": {},
        "by_analysis_type": {},
        "avg_risk_score": 0,
    }
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT verdict, analysis_type, COUNT(*) AS cnt, "
                "       AVG(risk_score) AS avg_score "
                "FROM threat_analysis "
                "WHERE tenant_id = %s "
                "GROUP BY verdict, analysis_type",
                (tenant_id,),
            )
            total = 0
            score_sum = 0.0
            score_count = 0
            verdict_counts: Dict[str, int] = defaultdict(int)
            type_counts: Dict[str, int] = defaultdict(int)

            for row in cur.fetchall():
                cnt = row["cnt"]
                total += cnt
                v = row.get("verdict") or "unknown"
                t = row.get("analysis_type") or "unknown"
                verdict_counts[v] += cnt
                type_counts[t] += cnt
                if row.get("avg_score") is not None:
                    score_sum += float(row["avg_score"]) * cnt
                    score_count += cnt

            summary["total_analyses"] = total
            summary["by_verdict"] = dict(verdict_counts)
            summary["by_analysis_type"] = dict(type_counts)
            if score_count > 0:
                summary["avg_risk_score"] = round(score_sum / score_count, 1)
    except Exception as e:
        logger.warning(f"Analysis summary query failed (table may not exist): {e}")
    return summary


# -- graph queries (Neo4j — production, always available) -------------------

def _query_graph_data(tenant_id: str) -> Dict[str, Any]:
    """Query Neo4j for attack paths, toxic combinations, and internet-exposed resources.

    Neo4j is always available in production. Errors are propagated (not swallowed)
    so they surface in the API response and logs.
    """
    from ..graph.graph_queries import SecurityGraphQueries

    gq = SecurityGraphQueries()
    try:
        attack_paths = gq.attack_paths_from_internet(
            tenant_id=tenant_id, max_hops=5, min_severity="high"
        )
        toxic_combinations = gq.toxic_combinations(
            tenant_id=tenant_id, min_threats=2
        )
        exposed = gq.internet_exposed_resources(tenant_id=tenant_id)

        return {
            "attack_paths": attack_paths,
            "toxic_combinations": toxic_combinations,
            "internet_exposed": {"total": len(exposed), "resources": exposed},
        }
    finally:
        gq.close()
