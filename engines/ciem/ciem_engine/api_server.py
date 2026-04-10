"""
CIEM Engine API Server

FastAPI server for log collection, detection findings, and identity analytics.
Port: 8025

Endpoints:
  POST /api/v1/scan                       — Start log collection (K8s Job)
  GET  /api/v1/log-collection/events      — Query normalized events
  GET  /api/v1/log-collection/sources     — List discovered log sources
  GET  /api/v1/log-collection/stats       — Event statistics

  GET  /api/v1/ciem/findings              — Query CIEM detection findings
  GET  /api/v1/ciem/findings/{finding_id} — Get single finding detail
  GET  /api/v1/ciem/dashboard             — Dashboard summary (counts, trends)
  GET  /api/v1/ciem/identities            — Identity risk summary
  GET  /api/v1/ciem/top-rules             — Top triggered rules
  GET  /api/v1/ciem/report/{scan_run_id}  — Scan report

  GET  /api/v1/health/live                — Liveness probe
  GET  /api/v1/health/ready               — Readiness probe
"""

import os
import sys
import json
import time
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from engine_common.logger import setup_logger
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.orchestration import get_orchestration_metadata
from engine_common.job_creator import create_engine_job

logger = setup_logger(__name__, engine_name="engine-ciem")

app = FastAPI(
    title="Log Collection Engine API",
    description="Cloud log collection, normalization, and querying",
    version="1.0.0",
)
configure_telemetry("engine-ciem", app)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scanner job config
SCANNER_IMAGE = os.getenv("CIEM_SCANNER_IMAGE", "yadavanup84/engine-ciem:v-std-cols")
SCANNER_CPU = os.getenv("SCANNER_CPU_REQUEST", "500m")
SCANNER_MEM = os.getenv("SCANNER_MEM_REQUEST", "2Gi")


# ── Models ──

class ScanRequest(BaseModel):
    scan_run_id: str
    tenant_id: str = "default-tenant"
    provider: str = "aws"
    account_id: str = ""
    lookback_hours: int = 24
    max_events: int = 100000
    source_types: Optional[List[str]] = None  # ["cloudtrail", "vpc_flow", "alb"]


class ScanResponse(BaseModel):
    scan_run_id: str
    status: str
    message: str


# ── Health ──

@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def health_ready():
    return {"status": "ready"}


@app.get("/")
async def root():
    return {"service": "Log Collection Engine", "version": "1.0.0"}


# ── Scan ──

@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_log_collection(request: ScanRequest):
    """Start log collection by creating a K8s Job."""
    scan_run_id = request.scan_run_id

    try:
        meta = get_orchestration_metadata(scan_run_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    tenant_id = meta.get("tenant_id") or request.tenant_id
    provider = (meta.get("provider") or request.provider).lower()

    extra_env = []
    if request.lookback_hours != 24:
        from kubernetes import client as k8s_client
        extra_env.append(k8s_client.V1EnvVar(name="LOG_LOOKBACK_HOURS", value=str(request.lookback_hours)))
    if request.max_events != 100000:
        from kubernetes import client as k8s_client
        extra_env.append(k8s_client.V1EnvVar(name="LOG_MAX_EVENTS", value=str(request.max_events)))

    try:
        job_name = create_engine_job(
            engine_name="log-collection",
            scan_id=scan_run_id,
            scan_run_id=scan_run_id,
            image=SCANNER_IMAGE,
            cpu_request=SCANNER_CPU,
            mem_request=SCANNER_MEM,
            active_deadline_seconds=3600,
            extra_env=extra_env or None,
        )
    except Exception as e:
        logger.error(f"Failed to create log collection Job: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create Job: {e}")

    return ScanResponse(
        scan_run_id=scan_run_id,
        status="running",
        message=f"Log collection Job '{job_name}' created (image={SCANNER_IMAGE})",
    )


# ── Query Events ──

def _get_db_conn():
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("LOG_DB_HOST", os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost"))),
        port=int(os.getenv("LOG_DB_PORT", os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432")))),
        database=os.getenv("LOG_DB_NAME", os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")),
        user=os.getenv("LOG_DB_USER", os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres"))),
        password=os.getenv("LOG_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))),
    )


@app.get("/api/v1/log-collection/events")
async def query_events(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    actor_principal: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    limit: int = Query(100, le=10000),
    offset: int = Query(0),
):
    """Query normalized log events with filters."""
    import psycopg2.extras
    conn = _get_db_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions = ["tenant_id = %s"]
            params = [tenant_id]

            if scan_run_id:
                conditions.append("scan_run_id = %s")
                params.append(scan_run_id)
            if source_type:
                conditions.append("source_type = %s")
                params.append(source_type)
            if category:
                conditions.append("category = %s")
                params.append(category)
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if resource_uid:
                conditions.append("resource_uid = %s")
                params.append(resource_uid)
            if actor_principal:
                conditions.append("actor_principal LIKE %s")
                params.append(f"%{actor_principal}%")
            if operation:
                conditions.append("operation = %s")
                params.append(operation)

            where = " AND ".join(conditions)
            params.extend([limit, offset])

            cur.execute(f"""
                SELECT event_id, event_time, category, source_type, severity,
                       service, operation, outcome, error_code,
                       actor_principal, actor_ip, actor_user_agent,
                       resource_uid, resource_type, resource_name, resource_region,
                       risk_indicators, asset_matched
                FROM log_events
                WHERE {where}
                ORDER BY event_time DESC
                LIMIT %s OFFSET %s
            """, params)
            events = [dict(r) for r in cur.fetchall()]

            # Get total count
            cur.execute(f"SELECT count(*) FROM log_events WHERE {where}", params[:-2])
            total = cur.fetchone()["count"]

        return {"total": total, "events": events, "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/log-collection/stats")
async def event_stats(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    """Get event statistics by source type, category, severity."""
    import psycopg2.extras
    conn = _get_db_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT
                    count(*) AS total_events,
                    count(DISTINCT source_type) AS source_types,
                    count(DISTINCT service) AS services,
                    count(DISTINCT actor_principal) AS unique_actors,
                    count(DISTINCT resource_uid) AS unique_resources,
                    min(event_time) AS earliest,
                    max(event_time) AS latest
                FROM log_events
                WHERE tenant_id = %s {scan_filter}
            """, params)
            summary = dict(cur.fetchone())

            cur.execute(f"""
                SELECT source_type, count(*) AS count
                FROM log_events WHERE tenant_id = %s {scan_filter}
                GROUP BY source_type ORDER BY count DESC
            """, params)
            by_source = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT severity, count(*) AS count
                FROM log_events WHERE tenant_id = %s {scan_filter}
                GROUP BY severity ORDER BY count DESC
            """, params)
            by_severity = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT operation, count(*) AS count
                FROM log_events WHERE tenant_id = %s {scan_filter}
                GROUP BY operation ORDER BY count DESC LIMIT 20
            """, params)
            top_operations = [dict(r) for r in cur.fetchall()]

        return {
            "summary": summary,
            "by_source": by_source,
            "by_severity": by_severity,
            "top_operations": top_operations,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/log-collection/sources")
async def list_log_sources(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    """List discovered log sources."""
    import psycopg2.extras
    conn = _get_db_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT source_type, source_bucket, source_region,
                       count(*) AS event_count,
                       min(event_time) AS earliest,
                       max(event_time) AS latest
                FROM log_events
                WHERE tenant_id = %s {scan_filter}
                GROUP BY source_type, source_bucket, source_region
                ORDER BY event_count DESC
            """, params)
            sources = [dict(r) for r in cur.fetchall()]

        return {"sources": sources}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
# CIEM Findings & Dashboard
# ═══════════════════════════════════════════════════════════════

def _get_ciem_conn():
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
        user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                 os.getenv("DB_PASSWORD", ""))),
    )


@app.get("/api/v1/ciem/findings")
async def query_findings(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    rule_source: Optional[str] = Query(None),
    primary_engine: Optional[str] = Query(None),
    actor_principal: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    limit: int = Query(100, le=10000),
    offset: int = Query(0),
):
    """Query CIEM detection findings with filters."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions = ["tenant_id = %s"]
            params = [tenant_id]

            if scan_run_id:
                conditions.append("scan_run_id = %s")
                params.append(scan_run_id)
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if rule_source:
                conditions.append("rule_source = %s")
                params.append(rule_source)
            if primary_engine:
                conditions.append("primary_engine = %s")
                params.append(primary_engine)
            if actor_principal:
                conditions.append("actor_principal LIKE %s")
                params.append(f"%{actor_principal}%")
            if resource_uid:
                conditions.append("resource_uid LIKE %s")
                params.append(f"%{resource_uid}%")
            if rule_id:
                conditions.append("rule_id = %s")
                params.append(rule_id)
            if service:
                conditions.append("service = %s")
                params.append(service)

            where = " AND ".join(conditions)

            cur.execute(f"""
                SELECT finding_id, scan_run_id, rule_id, rule_source,
                       severity, status, primary_engine,
                       resource_uid, resource_type, resource_name,
                       account_id, region, provider,
                       actor_principal, actor_ip,
                       event_time, service, operation,
                       title, description, action_category,
                       mitre_tactics, mitre_techniques
                FROM ciem_findings
                WHERE {where}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    event_time DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])
            findings = [dict(r) for r in cur.fetchall()]

            cur.execute(f"SELECT count(*) FROM ciem_findings WHERE {where}", params)
            total = cur.fetchone()["count"]

        return {"total": total, "findings": findings, "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get detailed finding by ID."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ciem_findings WHERE finding_id = %s", (finding_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
            return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


def _query_ciem_scan_trend(cur, tenant_id: str) -> list:
    """Last 8 CIEM scan runs — identities_at_risk and rules_triggered per scan."""
    try:
        cur.execute(
            """
            SELECT
                to_char(MAX(event_time), 'Mon DD')                      AS date,
                COUNT(*)                                                  AS total,
                COUNT(*) FILTER (WHERE severity = 'critical')            AS critical,
                COUNT(*) FILTER (WHERE severity = 'high')                AS high,
                COUNT(*) FILTER (WHERE severity = 'medium')              AS medium,
                COUNT(*) FILTER (WHERE severity = 'low')                 AS low,
                COUNT(DISTINCT actor_principal)
                    FILTER (WHERE actor_principal IS NOT NULL
                              AND actor_principal != '')                  AS identities_at_risk,
                COUNT(DISTINCT rule_id)                                   AS rules_triggered
            FROM ciem_findings
            WHERE tenant_id = %s AND scan_run_id IS NOT NULL
            GROUP BY scan_run_id
            ORDER BY MAX(event_time) DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        rows = list(reversed(cur.fetchall()))
        result = []
        for row in rows:
            total = int(row["total"] or 0)
            crit  = int(row["critical"] or 0)
            high  = int(row["high"] or 0)
            med   = int(row["medium"] or 0)
            low   = int(row["low"] or 0)
            if total > 0:
                weight = crit * 4 + high * 3 + med * 2 + low * 1
                pass_rate = max(0, min(100, round(100 - (weight / (total * 4)) * 100)))
            else:
                pass_rate = 100
            result.append({
                "date":               row["date"] or "",
                "total":              total,
                "critical":           crit,
                "high":               high,
                "medium":             med,
                "low":                low,
                "pass_rate":          pass_rate,
                "identities_at_risk": int(row["identities_at_risk"] or 0),
                "rules_triggered":    int(row["rules_triggered"] or 0),
            })
        return result
    except Exception:
        logger.warning("ciem scan_trend query failed", exc_info=True)
        return []


@app.get("/api/v1/ciem/dashboard")
async def ciem_dashboard(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    """CIEM dashboard — summary counts, severity breakdown, engine breakdown, trends."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            # Summary counts
            cur.execute(f"""
                SELECT
                    count(*) AS total_findings,
                    count(DISTINCT rule_id) AS rules_triggered,
                    count(DISTINCT actor_principal) FILTER (WHERE actor_principal != '') AS unique_actors,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS unique_resources,
                    count(DISTINCT account_id) FILTER (WHERE account_id != '') AS accounts,
                    count(*) FILTER (WHERE rule_source = 'correlation') AS l2_findings,
                    count(*) FILTER (WHERE rule_source = 'baseline') AS l3_findings
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
            """, params)
            summary = dict(cur.fetchone())

            # By severity
            cur.execute(f"""
                SELECT severity, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY severity ORDER BY
                    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            """, params)
            by_severity = [dict(r) for r in cur.fetchall()]

            # By engine
            cur.execute(f"""
                SELECT primary_engine, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY primary_engine ORDER BY count DESC
            """, params)
            by_engine = [dict(r) for r in cur.fetchall()]

            # By rule_source (L1/L2/L3)
            cur.execute(f"""
                SELECT rule_source, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                GROUP BY rule_source ORDER BY count DESC
            """, params)
            by_source = [dict(r) for r in cur.fetchall()]

            # By action category
            cur.execute(f"""
                SELECT action_category, count(*) AS count
                FROM ciem_findings WHERE tenant_id = %s {scan_filter}
                AND action_category != ''
                GROUP BY action_category ORDER BY count DESC
            """, params)
            by_category = [dict(r) for r in cur.fetchall()]

            # Top 10 critical/high findings
            cur.execute(f"""
                SELECT finding_id, rule_id, severity, title,
                       actor_principal, resource_uid, event_time
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                AND severity IN ('critical', 'high')
                ORDER BY event_time DESC LIMIT 10
            """, params)
            top_critical = [dict(r) for r in cur.fetchall()]

            # Scan trend (last 8 scans, oldest-first — for sparklines)
            scan_trend = _query_ciem_scan_trend(cur, tenant_id)

        return {
            "summary": summary,
            "by_severity": by_severity,
            "by_engine": by_engine,
            "by_rule_source": by_source,
            "by_category": by_category,
            "top_critical": top_critical,
            "scan_trend": scan_trend,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/identities")
async def identity_summary(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
):
    """Identity risk summary — top actors by finding count and severity."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT
                    actor_principal,
                    count(*) AS total_findings,
                    count(*) FILTER (WHERE severity = 'critical') AS critical,
                    count(*) FILTER (WHERE severity = 'high') AS high,
                    count(*) FILTER (WHERE severity = 'medium') AS medium,
                    count(DISTINCT rule_id) AS rules_triggered,
                    count(DISTINCT service) AS services_used,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS resources_touched,
                    array_agg(DISTINCT actor_ip) FILTER (WHERE actor_ip != '') AS source_ips,
                    max(event_time) AS last_activity
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                AND actor_principal IS NOT NULL AND actor_principal != ''
                GROUP BY actor_principal
                ORDER BY
                    count(*) FILTER (WHERE severity = 'critical') DESC,
                    count(*) FILTER (WHERE severity = 'high') DESC,
                    count(*) DESC
                LIMIT %s
            """, params + [limit])
            identities = [dict(r) for r in cur.fetchall()]

        return {"identities": identities, "count": len(identities)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/top-rules")
async def top_rules(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    limit: int = Query(20, le=100),
):
    """Top triggered detection rules by finding count."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            scan_filter = "AND scan_run_id = %s" if scan_run_id else ""
            params = [tenant_id, scan_run_id] if scan_run_id else [tenant_id]

            cur.execute(f"""
                SELECT
                    rule_id,
                    rule_source,
                    severity,
                    title,
                    primary_engine,
                    action_category,
                    count(*) AS finding_count,
                    count(DISTINCT actor_principal) FILTER (WHERE actor_principal != '') AS unique_actors,
                    count(DISTINCT resource_uid) FILTER (WHERE resource_uid != '') AS unique_resources
                FROM ciem_findings
                WHERE tenant_id = %s {scan_filter}
                GROUP BY rule_id, rule_source, severity, title, primary_engine, action_category
                ORDER BY count(*) DESC
                LIMIT %s
            """, params + [limit])
            rules = [dict(r) for r in cur.fetchall()]

        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/v1/ciem/report/{scan_run_id}")
async def scan_report(scan_run_id: str):
    """Get CIEM scan report with full summary."""
    import psycopg2.extras
    conn = _get_ciem_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ciem_report WHERE scan_run_id = %s", (scan_run_id,))
            report = cur.fetchone()
            if not report:
                raise HTTPException(status_code=404, detail=f"Report not found for {scan_run_id}")
            return dict(report)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
