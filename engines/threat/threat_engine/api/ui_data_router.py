"""
Threat Engine — Unified UI Data Endpoint

GET /api/v1/threat/ui-data

Returns detection-level threat data (grouped, risk-scored, MITRE-mapped).
Detections = grouped threats (1 detection = N atomic findings).
Source: threat_detections JOIN threat_analysis.
Consumed by: threats BFF, dashboard BFF.

Atomic PASS/FAIL findings live in the check engine (/check/api/v1/findings)
and are shown on the misconfig page — NOT here.
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


def _ts(val) -> Optional[str]:
    return str(val) if val else None


_SEV_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

@router.get("/api/v1/threat/ui-data")
async def get_threat_ui_data(
    tenant_id: str = Query(..., description="Tenant identifier"),
    scan_run_id: Optional[str] = Query(None, description="Scan run ID (default: latest)"),
    limit: int = Query(200, ge=1, le=2000, description="Max detections to return"),
    offset: int = Query(0, ge=0),
    days: int = Query(30, ge=1, le=365, description="Trend lookback days"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    account_id: Optional[str] = Query(None, description="Filter by account"),
    region: Optional[str] = Query(None, description="Filter by region"),
    threat_category: Optional[str] = Query(None, description="Filter by threat category"),
):
    """
    Unified UI data endpoint — returns DETECTION-level threat data.

    Each row = a grouped threat (N findings → 1 detection) with risk score,
    blast radius, verdict, and attack chain from threat_analysis.

    Serves: threats page, dashboard (threat section).
    Misconfig page uses check engine directly.
    """
    start = time.time()
    conn = None

    try:
        conn = _get_conn()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")

    try:
        # ------------------------------------------------------------------ #
        # 1. Resolve scan_id
        # ------------------------------------------------------------------ #
        scan_id = _resolve_scan_id(conn, tenant_id, scan_run_id)
        if not scan_id:
            return _empty_response()

        # ------------------------------------------------------------------ #
        # 2. Summary (KPIs — always unfiltered for full picture)
        # ------------------------------------------------------------------ #
        summary = _query_summary(conn, tenant_id, scan_id)

        # ------------------------------------------------------------------ #
        # 3. Paginated detections (with analysis JOIN + filters)
        # ------------------------------------------------------------------ #
        threats, total_filtered = _query_threats(
            conn, tenant_id, scan_id,
            limit, offset, severity, account_id, region, threat_category,
        )

        # ------------------------------------------------------------------ #
        # 4. MITRE matrix (from detections)
        # ------------------------------------------------------------------ #
        mitre_matrix = _query_mitre_matrix(conn, tenant_id, scan_id)

        # ------------------------------------------------------------------ #
        # 5. Trend (detection-level, last N days)
        # ------------------------------------------------------------------ #
        trend = _query_trend(conn, tenant_id, days)

        # ------------------------------------------------------------------ #
        # 6. Top services / accounts / regions
        # ------------------------------------------------------------------ #
        top_services = _query_top_services(conn, tenant_id, scan_id)
        top_accounts = _query_top_accounts(conn, tenant_id, scan_id)
        top_regions = _query_top_regions(conn, tenant_id, scan_id)

        # ------------------------------------------------------------------ #
        # 7. Threat intelligence (from threat_intelligence table)
        # ------------------------------------------------------------------ #
        threat_intel = _query_intel(conn, tenant_id)

        # Release DB before graph queries
        conn.close()
        conn = None

        # ------------------------------------------------------------------ #
        # 8. Graph queries (Neo4j)
        # ------------------------------------------------------------------ #
        graph_data = _query_graph_data(tenant_id)

        duration_ms = (time.time() - start) * 1000
        logger.info(
            "UI data served",
            extra={"extra_fields": {
                "duration_ms": round(duration_ms, 1),
                "total_detections": summary["total_detections"],
            }},
        )

        return {
            "summary": summary,
            "threats": threats,
            "total": total_filtered,
            "trend": trend,
            "mitre_matrix": mitre_matrix,
            "top_services": top_services,
            "top_accounts": top_accounts,
            "top_regions": top_regions,
            "attack_paths": graph_data["attack_paths"],
            "toxic_combinations": graph_data["toxic_combinations"],
            "internet_exposed": graph_data["internet_exposed"],
            "threat_intel": threat_intel,
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
            "total_detections": 0, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "avg_risk_score": 0, "by_category": {},
            "by_verdict": {}, "total_findings": 0,
        },
        "threats": [],
        "total": 0,
        "trend": [],
        "mitre_matrix": [],
        "top_services": [],
        "top_accounts": [],
        "top_regions": [],
        "attack_paths": [],
        "toxic_combinations": [],
        "internet_exposed": {"total": 0, "resources": []},
        "threat_intel": [],
    }


def _resolve_scan_id(conn, tenant_id: str, scan_run_id: Optional[str]) -> Optional[str]:
    """Resolve scan_id filter for threat_detections.

    Returns scan_id string, or "__all__" meaning don't filter by scan_id
    (for "latest" when detections span multiple scans — show all).
    """
    with conn.cursor() as cur:
        if scan_run_id and scan_run_id != "latest":
            # Specific scan requested
            cur.execute(
                "SELECT DISTINCT scan_id FROM threat_detections "
                "WHERE tenant_id = %s AND scan_id = %s LIMIT 1",
                (tenant_id, scan_run_id),
            )
            row = cur.fetchone()
            if row:
                return row[0]
            return None
        else:
            # "latest" — check if tenant has any detections at all
            cur.execute(
                "SELECT COUNT(*) FROM threat_detections WHERE tenant_id = %s",
                (tenant_id,),
            )
            cnt = cur.fetchone()[0]
            if cnt > 0:
                return "__all__"
            return None


# -- summary ----------------------------------------------------------------

def _scan_filter(scan_id: str) -> tuple:
    """Return (WHERE fragment, params list) for scan_id filtering."""
    if scan_id == "__all__":
        return "", []
    return " AND d.scan_id = %s", [scan_id]


def _query_summary(conn, tenant_id: str, scan_id: str) -> dict:
    """KPIs from threat_detections + threat_analysis."""
    summary: Dict[str, Any] = {
        "total_detections": 0, "critical": 0, "high": 0, "medium": 0,
        "low": 0, "avg_risk_score": 0, "by_category": {},
        "by_verdict": {}, "total_findings": 0,
    }
    sf, sp = _scan_filter(scan_id)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT d.severity, d.threat_category, COUNT(*) AS cnt "
            f"FROM threat_detections d "
            f"WHERE d.tenant_id = %s{sf} "
            f"GROUP BY d.severity, d.threat_category",
            [tenant_id] + sp,
        )
        for row in cur.fetchall():
            sev = (row["severity"] or "low").lower()
            cat = row["threat_category"] or "uncategorized"
            cnt = row["cnt"]
            summary[sev] = summary.get(sev, 0) + cnt
            summary["total_detections"] += cnt
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + cnt

        cur.execute(
            f"SELECT a.verdict, COUNT(*) AS cnt, AVG(a.risk_score) AS avg_score "
            f"FROM threat_analysis a "
            f"JOIN threat_detections d ON a.detection_id = d.detection_id "
            f"WHERE d.tenant_id = %s{sf} "
            f"GROUP BY a.verdict",
            [tenant_id] + sp,
        )
        total_score = 0.0
        score_count = 0
        for row in cur.fetchall():
            v = row["verdict"] or "unknown"
            summary["by_verdict"][v] = row["cnt"]
            if row["avg_score"] is not None:
                total_score += float(row["avg_score"]) * row["cnt"]
                score_count += row["cnt"]
        if score_count > 0:
            summary["avg_risk_score"] = round(total_score / score_count, 1)

        # Total atomic findings
        cur.execute(
            "SELECT COUNT(*) FROM threat_findings WHERE tenant_id = %s",
            (tenant_id,),
        )
        row = cur.fetchone()
        summary["total_findings"] = row["count"] if row else 0

    return summary


# -- threats (detections + analysis) ----------------------------------------

def _query_threats(
    conn, tenant_id: str, scan_id: str,
    limit: int, offset: int,
    severity: Optional[str], account_id: Optional[str],
    region: Optional[str], threat_category: Optional[str],
) -> tuple:
    """Query threat_detections JOIN threat_analysis with finding_count."""
    where_parts = ["d.tenant_id = %s"]
    params: list = [tenant_id]
    if scan_id != "__all__":
        where_parts.append("d.scan_id = %s")
        params.append(scan_id)

    if severity:
        where_parts.append("d.severity = %s")
        params.append(severity)
    if account_id:
        where_parts.append("d.account_id = %s")
        params.append(account_id)
    if region:
        where_parts.append("d.region = %s")
        params.append(region)
    if threat_category:
        where_parts.append("d.threat_category = %s")
        params.append(threat_category)

    where = " AND ".join(where_parts)

    threats: List[dict] = []
    total = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Total count
        cur.execute(f"SELECT COUNT(*) AS cnt FROM threat_detections d WHERE {where}", params)
        total = cur.fetchone()["cnt"]

        # Main query: detections + analysis + finding_count
        cur.execute(f"""
            SELECT
                d.detection_id,
                d.detection_type,
                d.rule_id,
                d.rule_name,
                d.resource_uid,
                d.resource_id,
                d.resource_type,
                d.account_id,
                d.region,
                d.provider,
                d.severity,
                d.confidence,
                d.status,
                d.threat_category,
                d.mitre_tactics,
                d.mitre_techniques,
                d.evidence,
                d.first_seen_at,
                d.last_seen_at,
                d.detection_timestamp,
                -- Analysis fields (LEFT JOIN — not all detections have analysis)
                a.risk_score,
                a.verdict,
                a.analysis_results,
                a.attack_chain,
                a.recommendations,
                -- Finding count: how many atomic findings this detection groups
                (SELECT COUNT(*) FROM threat_findings f
                 WHERE f.tenant_id = d.tenant_id
                   AND f.rule_id = d.rule_id
                   AND f.resource_uid = d.resource_uid
                ) AS finding_count
            FROM threat_detections d
            LEFT JOIN threat_analysis a ON a.detection_id = d.detection_id
            WHERE {where}
            ORDER BY
                COALESCE(a.risk_score, 0) DESC,
                CASE d.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                END,
                d.detection_timestamp DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        for row in cur.fetchall():
            evidence = _safe_json(row.get("evidence"))
            analysis_results = _safe_json(row.get("analysis_results"))
            blast = analysis_results.get("blast_radius", {})

            threats.append({
                "detection_id": str(row["detection_id"]),
                "detection_type": row["detection_type"],
                "rule_id": row.get("rule_id", ""),
                "rule_name": row.get("rule_name", ""),
                "title": row.get("rule_name") or row.get("detection_type", ""),
                "resource_uid": row.get("resource_uid", ""),
                "resource_type": row.get("resource_type", ""),
                "account_id": row.get("account_id", ""),
                "region": row.get("region", ""),
                "provider": row.get("provider", ""),
                "severity": row.get("severity", "medium"),
                "confidence": row.get("confidence", ""),
                "status": row.get("status", "open"),
                "threat_category": row.get("threat_category", ""),
                # Risk & analysis
                "risk_score": row.get("risk_score") or 0,
                "verdict": row.get("verdict") or "",
                "blast_radius": blast.get("reachable_count", 0),
                "finding_count": row.get("finding_count", 0),
                # MITRE
                "mitre_techniques": _safe_json(row.get("mitre_techniques")) or [],
                "mitre_tactics": _safe_json(row.get("mitre_tactics")) or [],
                # Attack chain
                "attack_chain": _safe_json(row.get("attack_chain")) or [],
                "recommendations": _safe_json(row.get("recommendations")) or [],
                # Evidence (from detection grouping)
                "evidence": evidence,
                # Timestamps
                "first_seen_at": _ts(row.get("first_seen_at")),
                "last_seen_at": _ts(row.get("last_seen_at")),
                "detected_at": _ts(row.get("detection_timestamp")),
            })

    return threats, total


# -- MITRE matrix -----------------------------------------------------------

def _query_mitre_matrix(conn, tenant_id: str, scan_id: str) -> List[dict]:
    """Build MITRE matrix from threat_detections."""
    matrix: List[dict] = []
    sf, sp = _scan_filter(scan_id)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                WITH technique_counts AS (
                    SELECT
                        CASE
                            WHEN jsonb_typeof(elem) = 'object' THEN elem->>'id'
                            WHEN jsonb_typeof(elem) = 'string' THEN elem #>> '{{}}'
                            ELSE NULL
                        END AS technique_id,
                        COUNT(*) AS detection_count
                    FROM threat_detections d,
                         jsonb_array_elements(COALESCE(d.mitre_techniques, '[]'::jsonb)) AS elem
                    WHERE d.tenant_id = %s{sf}
                      AND d.mitre_techniques IS NOT NULL
                      AND d.mitre_techniques != '[]'::jsonb
                    GROUP BY 1
                )
                SELECT tc.technique_id, tc.detection_count,
                       mr.technique_name, mr.tactics, mr.severity_base
                FROM technique_counts tc
                LEFT JOIN mitre_technique_reference mr ON tc.technique_id = mr.technique_id
                WHERE tc.technique_id IS NOT NULL
                ORDER BY tc.detection_count DESC
            """, [tenant_id] + sp)

            for row in cur.fetchall():
                tactics = _safe_json(row.get("tactics"))
                if isinstance(tactics, str):
                    tactics = [tactics]
                matrix.append({
                    "technique_id": row["technique_id"],
                    "technique_name": row.get("technique_name") or row["technique_id"],
                    "tactics": tactics if isinstance(tactics, list) else [],
                    "count": row["detection_count"],
                    "severity_base": row.get("severity_base") or "medium",
                })
    except Exception as e:
        logger.warning(f"MITRE matrix query failed: {e}")
    return matrix


# -- trend ------------------------------------------------------------------

def _query_trend(conn, tenant_id: str, days: int) -> List[dict]:
    """Detection-level trend over last N days."""
    trend: List[dict] = []
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT DATE(detection_timestamp) AS d, severity, COUNT(*) AS cnt "
                "FROM threat_detections "
                "WHERE tenant_id = %s AND detection_timestamp >= %s "
                "GROUP BY 1, 2 ORDER BY 1",
                (tenant_id, cutoff),
            )
            date_map: Dict[str, Dict[str, Any]] = defaultdict(
                lambda: {"date": "", "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
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


# -- top services / accounts / regions -------------------------------------

def _query_top_services(conn, tenant_id: str, scan_id: str) -> List[dict]:
    result = []
    sf, sp = _scan_filter(scan_id)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT COALESCE(resource_type, 'unknown') AS service, "
                f"  severity, COUNT(*) AS cnt "
                f"FROM threat_detections d "
                f"WHERE d.tenant_id = %s{sf} "
                f"GROUP BY 1, 2",
                [tenant_id] + sp,
            )
            svc_map: Dict[str, Dict[str, Any]] = defaultdict(
                lambda: {"service": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            )
            for row in cur.fetchall():
                svc = row["service"]
                sev = (row["severity"] or "low").lower()
                svc_map[svc]["service"] = svc
                svc_map[svc]["count"] += row["cnt"]
                svc_map[svc][sev] = svc_map[svc].get(sev, 0) + row["cnt"]
            result = sorted(svc_map.values(), key=lambda x: x["count"], reverse=True)[:20]
    except Exception as e:
        logger.warning(f"Top services query failed: {e}")
    return result


def _query_top_accounts(conn, tenant_id: str, scan_id: str) -> List[dict]:
    result = []
    sf, sp = _scan_filter(scan_id)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT account_id, severity, COUNT(*) AS cnt "
                f"FROM threat_detections d "
                f"WHERE d.tenant_id = %s{sf} "
                f"GROUP BY account_id, severity",
                [tenant_id] + sp,
            )
            acct_map: Dict[str, Dict[str, Any]] = defaultdict(
                lambda: {"account_id": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            )
            for row in cur.fetchall():
                acct = row["account_id"] or "unknown"
                sev = (row["severity"] or "low").lower()
                acct_map[acct]["account_id"] = acct
                acct_map[acct]["count"] += row["cnt"]
                acct_map[acct][sev] = acct_map[acct].get(sev, 0) + row["cnt"]
            result = sorted(acct_map.values(), key=lambda x: x["count"], reverse=True)
    except Exception as e:
        logger.warning(f"Top accounts query failed: {e}")
    return result


def _query_top_regions(conn, tenant_id: str, scan_id: str) -> List[dict]:
    result = []
    sf, sp = _scan_filter(scan_id)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT region, severity, COUNT(*) AS cnt "
                f"FROM threat_detections d "
                f"WHERE d.tenant_id = %s{sf} "
                f"GROUP BY region, severity",
                [tenant_id] + sp,
            )
            region_map: Dict[str, Dict[str, Any]] = defaultdict(
                lambda: {"region": "", "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            )
            for row in cur.fetchall():
                rgn = row["region"] or "unknown"
                sev = (row["severity"] or "low").lower()
                region_map[rgn]["region"] = rgn
                region_map[rgn]["count"] += row["cnt"]
                region_map[rgn][sev] = region_map[rgn].get(sev, 0) + row["cnt"]
            result = sorted(region_map.values(), key=lambda x: x["count"], reverse=True)
    except Exception as e:
        logger.warning(f"Top regions query failed: {e}")
    return result


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


# -- graph queries (Neo4j) --------------------------------------------------

def _query_graph_data(tenant_id: str) -> Dict[str, Any]:
    """Query Neo4j for attack paths, toxic combinations, internet-exposed."""
    from ..graph.graph_queries import SecurityGraphQueries

    gq = SecurityGraphQueries()
    try:
        attack_paths = gq.attack_paths(
            tenant_id=tenant_id, max_hops=5, min_severity="medium",
            entry_point="all",
        )
        toxic_combinations = gq.toxic_combinations(tenant_id=tenant_id)

        # Internet exposed = deduplicated resources from attack paths
        seen_uids: set = set()
        exposed = []
        for p in attack_paths:
            uid = p.get("resource_uid", "")
            if uid and uid not in seen_uids:
                seen_uids.add(uid)
                exposed.append(p)

        return {
            "attack_paths": attack_paths,
            "toxic_combinations": toxic_combinations,
            "internet_exposed": {"total": len(exposed), "resources": exposed},
        }
    finally:
        gq.close()
