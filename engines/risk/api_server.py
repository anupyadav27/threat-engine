"""
Risk Engine API Server — Port 8009

Endpoints:
  POST /api/v1/scan          — Run full 3-stage risk pipeline
  GET  /api/v1/report/{id}   — Retrieve risk report
  GET  /api/v1/scenarios/{id} — List risk scenarios for a scan
  GET  /api/v1/trends/{tenant_id} — Get risk trend data
  GET  /api/v1/health/live   — Liveness probe
  GET  /api/v1/health/ready  — Readiness probe
  GET  /api/v1/metrics       — Prometheus metrics
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import psycopg2
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database connection pools
# ---------------------------------------------------------------------------

_risk_pool = None
_discovery_pool = None
_onboarding_pool = None
_external_pool = None


def _get_pool(db_name: str, env_prefix: str):
    """Create a psycopg2 connection for a database."""
    return psycopg2.connect(
        host=os.getenv(f"{env_prefix}_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv(f"{env_prefix}_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv(f"{env_prefix}_DB_NAME", db_name),
        user=os.getenv(f"{env_prefix}_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv(f"{env_prefix}_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def get_risk_conn():
    global _risk_pool
    if _risk_pool is None or _risk_pool.closed:
        _risk_pool = _get_pool("threat_engine_risk", "RISK")
    return _risk_pool


def get_discovery_conn():
    global _discovery_pool
    if _discovery_pool is None or _discovery_pool.closed:
        _discovery_pool = _get_pool("threat_engine_discoveries", "DISCOVERY")
    return _discovery_pool


def get_onboarding_conn():
    global _onboarding_pool
    if _onboarding_pool is None or _onboarding_pool.closed:
        _onboarding_pool = _get_pool("threat_engine_onboarding", "ONBOARDING")
    return _onboarding_pool


def get_external_conn():
    global _external_pool
    if _external_pool is None or _external_pool.closed:
        try:
            _external_pool = _get_pool("threat_engine_external", "EXTERNAL")
        except Exception:
            logger.warning("External DB not available — EPSS cache disabled")
            return None
    return _external_pool


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Risk engine starting on port 8009")
    yield
    # Cleanup connections
    for pool in [_risk_pool, _discovery_pool, _onboarding_pool, _external_pool]:
        if pool and not pool.closed:
            pool.close()
    logger.info("Risk engine shut down")


app = FastAPI(
    title="Risk Engine",
    description="FAIR model financial risk quantification",
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

_scan_count = 0
_scan_errors = 0
_last_scan_duration_ms = 0

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    scan_run_id: str
    tenant_id: str
    account_id: str
    provider: str = "aws"


class ScanResponse(BaseModel):
    risk_scan_id: str
    scan_run_id: str
    status: str
    transformed_count: int
    scenario_count: int
    total_exposure_likely: float
    duration_ms: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/api/v1/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    """Run the full 3-stage risk quantification pipeline."""
    global _scan_count, _scan_errors, _last_scan_duration_ms

    scan_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    start_time = time.time()

    try:
        risk_conn = get_risk_conn()
        onboarding_conn = get_onboarding_conn()
        external_conn = get_external_conn()

        # Stage 1: ETL — Transform
        # ETL opens its own per-engine DB connections internally
        from engines.risk.etl.risk_etl import RiskETL
        etl = RiskETL(risk_conn, onboarding_conn, external_conn)
        transformed_count = etl.run(
            scan_id, request.scan_run_id,
            request.tenant_id, request.account_id, request.provider,
        )

        # Stage 2: Evaluate — FAIR model
        from engines.risk.evaluator.risk_evaluator import RiskEvaluator
        evaluator = RiskEvaluator(risk_conn)
        scenario_count = evaluator.run(
            scan_id, request.scan_run_id,
            request.tenant_id, request.account_id, request.provider,
        )

        # Stage 3: Report — Aggregate
        from engines.risk.reporter.risk_reporter import RiskReporter
        reporter = RiskReporter(risk_conn)
        report = reporter.run(
            scan_id, request.scan_run_id,
            request.tenant_id, request.account_id, request.provider,
            started_at=started_at,
        )

        # Stage 4: Coordinate — Update orchestration
        from engines.risk.db.risk_db_writer import RiskDBWriter
        writer = RiskDBWriter(risk_conn)
        writer.update_orchestration(request.scan_run_id, scan_id, onboarding_conn)

        duration_ms = int((time.time() - start_time) * 1000)
        _scan_count += 1
        _last_scan_duration_ms = duration_ms

        return ScanResponse(
            risk_scan_id=scan_id,
            scan_run_id=request.scan_run_id,
            status="completed",
            transformed_count=transformed_count,
            scenario_count=scenario_count,
            total_exposure_likely=report.get("total_exposure_likely", 0),
            duration_ms=duration_ms,
        )

    except Exception as exc:
        _scan_errors += 1
        logger.error("Risk scan failed: %s", exc, exc_info=True)
        # Write failed report
        try:
            from engines.risk.db.risk_db_writer import RiskDBWriter
            writer = RiskDBWriter(get_risk_conn())
            writer.insert_report({
                "risk_scan_id": scan_id,
                "scan_run_id": request.scan_run_id,
                "tenant_id": request.tenant_id,
                "account_id": request.account_id,
                "provider": request.provider,
                "status": "failed",
                "error_message": str(exc),
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc),
            })
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/report/{scan_id}")
async def get_report(scan_id: str):
    """Retrieve the risk report for a scan."""
    conn = get_risk_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT risk_scan_id::text, scan_run_id::text, tenant_id,
                   account_id, provider,
                   total_scenarios, critical_scenarios, high_scenarios,
                   medium_scenarios, low_scenarios,
                   total_exposure_min, total_exposure_max, total_exposure_likely,
                   total_regulatory_exposure,
                   engine_breakdown, top_scenarios, scenario_type_breakdown,
                   frameworks_at_risk,
                   vs_previous_likely, vs_previous_pct,
                   currency, status, scan_duration_ms
            FROM risk_report
            WHERE risk_scan_id = %s::uuid
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")

        return {
            "risk_scan_id": row[0],
            "scan_run_id": row[1],
            "tenant_id": row[2],
            "account_id": row[3],
            "provider": row[4],
            "total_scenarios": row[5],
            "critical_scenarios": row[6],
            "high_scenarios": row[7],
            "medium_scenarios": row[8],
            "low_scenarios": row[9],
            "total_exposure_min": float(row[10]) if row[10] else 0,
            "total_exposure_max": float(row[11]) if row[11] else 0,
            "total_exposure_likely": float(row[12]) if row[12] else 0,
            "total_regulatory_exposure": float(row[13]) if row[13] else 0,
            "engine_breakdown": row[14],
            "top_scenarios": row[15],
            "scenario_type_breakdown": row[16],
            "frameworks_at_risk": row[17],
            "vs_previous_likely": float(row[18]) if row[18] else None,
            "vs_previous_pct": float(row[19]) if row[19] else None,
            "currency": row[20],
            "status": row[21],
            "scan_duration_ms": row[22],
        }
    finally:
        cursor.close()


@app.get("/api/v1/scenarios/{scan_id}")
async def get_scenarios(
    scan_id: str,
    tier: Optional[str] = None,
    engine: Optional[str] = None,
    limit: int = 100,
):
    """List risk scenarios for a scan with optional filters."""
    conn = get_risk_conn()
    cursor = conn.cursor()
    try:
        query = """
            SELECT scenario_id::text, source_finding_id, source_engine,
                   asset_id, asset_arn, asset_type, scenario_type,
                   title, rule_id,
                   data_records_at_risk, data_sensitivity,
                   loss_event_frequency,
                   primary_loss_likely, regulatory_fine_max,
                   total_exposure_min, total_exposure_max, total_exposure_likely,
                   risk_tier, calculation_model,
                   account_id, region, csp
            FROM risk_scenarios
            WHERE risk_scan_id = %s::uuid
        """
        params = [scan_id]

        if tier:
            query += " AND risk_tier = %s"
            params.append(tier)
        if engine:
            query += " AND source_engine = %s"
            params.append(engine)

        query += " ORDER BY total_exposure_likely DESC LIMIT %s"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        cols = [desc[0] for desc in cursor.description]
        return [dict(zip(cols, row)) for row in rows]
    finally:
        cursor.close()


@app.get("/api/v1/trends/{tenant_id}")
async def get_trends(
    tenant_id: str,
    limit: int = 30,
):
    """Get risk trend data for a tenant."""
    conn = get_risk_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT scan_date, risk_scan_id::text,
                   total_exposure_likely, critical_scenarios, high_scenarios,
                   top_risk_type, top_risk_engine
            FROM risk_trends
            WHERE tenant_id = %s
            ORDER BY scan_date DESC
            LIMIT %s
        """, (tenant_id, limit))

        return [
            {
                "scan_date": str(r[0]),
                "risk_scan_id": r[1],
                "total_exposure_likely": float(r[2]) if r[2] else 0,
                "critical_scenarios": r[3] or 0,
                "high_scenarios": r[4] or 0,
                "top_risk_type": r[5],
                "top_risk_engine": r[6],
            }
            for r in cursor.fetchall()
        ]
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# Live risk score computation (from threat + compliance + IAM data)
# ---------------------------------------------------------------------------


def _get_threat_conn():
    """Connect to threat DB for live risk computation."""
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("THREAT_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("THREAT_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=5,
    )


def _get_compliance_conn():
    """Connect to compliance DB for live risk computation."""
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("COMPLIANCE_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=5,
    )


def _query_threat_stats(tenant_id: str) -> Dict[str, Any]:
    """Query threat_findings for severity distribution."""
    defaults = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                "threat_score": 0, "top_categories": []}
    try:
        conn = _get_threat_conn()
        try:
            cur = conn.cursor()
            # Severity counts
            cur.execute("""
                SELECT severity, count(*) FROM threat_findings
                WHERE tenant_id = %s GROUP BY severity
            """, (tenant_id,))
            for sev, cnt in cur.fetchall():
                if sev in defaults:
                    defaults[sev] = cnt
                defaults["total"] += cnt

            # Threat score from threat_report
            cur.execute("""
                SELECT threat_score FROM threat_report
                WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1
            """, (tenant_id,))
            row = cur.fetchone()
            if row and row[0]:
                defaults["threat_score"] = int(row[0])

            # Top categories
            cur.execute("""
                SELECT threat_category, count(*) as cnt FROM threat_findings
                WHERE tenant_id = %s
                GROUP BY threat_category ORDER BY cnt DESC LIMIT 5
            """, (tenant_id,))
            defaults["top_categories"] = [
                {"category": r[0] or "uncategorized", "count": r[1]} for r in cur.fetchall()
            ]
            cur.close()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Failed to query threat stats: %s", e)
    return defaults


def _query_compliance_stats(tenant_id: str) -> Dict[str, Any]:
    """Query compliance_report for pass/fail counts."""
    defaults = {"total_controls": 0, "controls_passed": 0, "controls_failed": 0,
                "compliance_pct": 0.0, "frameworks_at_risk": 0}
    try:
        conn = _get_compliance_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT total_controls, controls_passed, controls_failed, report_data
                FROM compliance_report WHERE tenant_id = %s
                ORDER BY created_at DESC LIMIT 1
            """, (tenant_id,))
            row = cur.fetchone()
            if row:
                total = row[0] or 0
                passed = row[1] or 0
                failed = row[2] or 0
                defaults["total_controls"] = total
                defaults["controls_passed"] = passed
                defaults["controls_failed"] = failed
                defaults["compliance_pct"] = round((passed / total * 100) if total > 0 else 0, 2)
                rd = row[3] or {}
                if isinstance(rd, dict):
                    fw_ids = rd.get("framework_ids", [])
                    defaults["frameworks_at_risk"] = len(fw_ids) if defaults["compliance_pct"] < 80 else 0
            cur.close()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Failed to query compliance stats: %s", e)
    return defaults


def _query_iam_stats(tenant_id: str) -> Dict[str, Any]:
    """Query iam_findings (in threat DB) for severity distribution."""
    defaults = {"total": 0, "critical": 0, "high": 0}
    try:
        conn = _get_threat_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT severity, count(*) FROM iam_findings
                WHERE tenant_id = %s GROUP BY severity
            """, (tenant_id,))
            for sev, cnt in cur.fetchall():
                if sev in ("critical", "high"):
                    defaults[sev] = cnt
                defaults["total"] += cnt
            cur.close()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("Failed to query IAM stats: %s", e)
    return defaults


def _compute_domain_score(critical: int, high: int, medium: int, low: int, total: int) -> int:
    """Compute a domain risk score (0-100) from severity distribution."""
    if total == 0:
        return 0
    weighted = critical * 10 + high * 5 + medium * 2 + low * 0.5
    # Normalize: cap at 100
    return max(0, min(100, int(weighted / max(total, 1) * 10)))


def _build_mitigation_roadmap(
    scenarios: list, overall_risk_score: int = 50
) -> List[Dict[str, Any]]:
    """Build a mitigation roadmap from FAIR scenarios.

    Groups scenarios by source_engine, computes reduction estimates,
    and returns actionable items sorted by priority.
    """
    if not scenarios or not isinstance(scenarios, list):
        return []

    # Group by source_engine
    by_engine: Dict[str, list] = {}
    for s in scenarios:
        if not isinstance(s, dict):
            continue
        eng = s.get("source_engine", "general")
        by_engine.setdefault(eng, []).append(s)

    from datetime import timedelta

    PRIORITY_MAP = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
    PRIORITY_DAYS = {"P0": 14, "P1": 30, "P2": 60, "P3": 90}
    ENGINE_ACTIONS = {
        "threat": "Remediate threat detections",
        "iam": "Enforce least-privilege IAM policies",
        "datasec": "Encrypt data stores and restrict access",
        "network": "Restrict public exposure and harden security groups",
        "compliance": "Close compliance control gaps",
        "container": "Harden container workloads and image scanning",
        "encryption": "Enable encryption at rest/transit and rotate keys",
        "database": "Restrict database access and enable audit logging",
        "ai_security": "Apply guardrails to AI/ML endpoints",
        "ciem": "Investigate anomalous identity activity",
        "check": "Remediate misconfigurations",
    }

    roadmap = []
    for eng, items in sorted(by_engine.items(), key=lambda x: -len(x[1])):
        worst_tier = "low"
        total_exposure = 0
        for s in items:
            tier = s.get("risk_tier", "medium")
            total_exposure += s.get("total_exposure_likely", 0)
            if {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(tier, 0) > \
               {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(worst_tier, 0):
                worst_tier = tier

        current_risk = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(worst_tier, 50)
        target_risk = max(10, current_risk - 30)
        reduction_pct = round((current_risk - target_risk) / max(current_risk, 1) * 100)
        est_cost = max(5000, int(total_exposure * 0.1))

        roadmap.append({
            "action": f"{ENGINE_ACTIONS.get(eng, 'Address findings')} ({len(items)} scenarios)",
            "current_risk": current_risk,
            "target_risk": target_risk,
            "reduction": reduction_pct,
            "cost": f"${est_cost:,}",
            "priority": PRIORITY_MAP.get(worst_tier, "P2"),
            "owner": f"{eng.replace('_', ' ').title()} Team",
            "due_date": (datetime.utcnow() + timedelta(days=PRIORITY_DAYS.get(PRIORITY_MAP.get(worst_tier, "P2"), 60))).strftime("%Y-%m-%d"),
            "domain": eng,
            "scenario_count": len(items),
            "total_exposure": round(total_exposure, 2),
        })

    roadmap.sort(key=lambda x: {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(x["priority"], 9))
    return roadmap


def _compute_live_dashboard(tenant_id: str) -> Dict[str, Any]:
    """Compute a live risk dashboard by aggregating threat + compliance + IAM data."""
    threat_stats = _query_threat_stats(tenant_id)
    compliance_stats = _query_compliance_stats(tenant_id)
    iam_stats = _query_iam_stats(tenant_id)

    # Per-domain risk scores
    threats_score = _compute_domain_score(
        threat_stats["critical"], threat_stats["high"],
        threat_stats.get("medium", 0), threat_stats.get("low", 0),
        threat_stats["total"],
    )
    if threat_stats["threat_score"] > 0:
        threats_score = max(threats_score, threat_stats["threat_score"])

    iam_score = _compute_domain_score(
        iam_stats["critical"], iam_stats["high"], 0, 0, iam_stats["total"],
    )

    # Compliance risk = inverse of compliance pass rate
    comp_pct = compliance_stats["compliance_pct"]
    compliance_score = max(0, min(100, int(100 - comp_pct))) if comp_pct > 0 else 100

    datasec_score = int(threats_score * 0.6)
    vuln_score = int(threats_score * 0.4)

    # Weighted overall: threats 30%, IAM 25%, compliance 20%, datasec 15%, vuln 10%
    overall_score = int(
        threats_score * 0.30 + iam_score * 0.25 + compliance_score * 0.20
        + datasec_score * 0.15 + vuln_score * 0.10
    )
    overall_score = max(0, min(100, overall_score))

    # Build risk register from top categories (UI-expected shape)
    risk_register: List[Dict[str, Any]] = []
    idx = 0
    for cat in threat_stats.get("top_categories", []):
        idx += 1
        tier = "critical" if cat["count"] > 50 else "high" if cat["count"] > 10 else "medium"
        inherent = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(tier, 50)
        risk_register.append({
            "id": f"RSK-{idx:03d}",
            "title": f"{cat['category'].replace('_', ' ').title()} — {cat['count']} findings",
            "category": "Threat Detection",
            "inherent": inherent,
            "residual": max(10, inherent - 20),
            "owner": "Security Team",
            "status": "open" if tier in ("critical", "high") else "monitoring",
            "source_engine": "threat",
            "finding_count": cat["count"],
            "risk_tier": tier,
        })
    if compliance_stats["controls_failed"] > 0:
        idx += 1
        tier = "high" if comp_pct < 50 else "medium"
        inherent = {"high": 75, "medium": 50}.get(tier, 50)
        risk_register.append({
            "id": f"RSK-{idx:03d}",
            "title": f"Compliance gaps — {compliance_stats['controls_failed']} failing controls",
            "category": "Compliance",
            "inherent": inherent,
            "residual": max(10, inherent - 20),
            "owner": "GRC Team",
            "status": "open",
            "source_engine": "compliance",
            "finding_count": compliance_stats["controls_failed"],
            "risk_tier": tier,
        })
    if iam_stats["critical"] + iam_stats["high"] > 0:
        idx += 1
        iam_total_ch = iam_stats["critical"] + iam_stats["high"]
        tier = "critical" if iam_stats["critical"] > 0 else "high"
        inherent = {"critical": 95, "high": 75}.get(tier, 75)
        risk_register.append({
            "id": f"RSK-{idx:03d}",
            "title": f"IAM posture — {iam_total_ch} critical/high findings",
            "category": "Identity & Access",
            "inherent": inherent,
            "residual": max(10, inherent - 20),
            "owner": "IAM Team",
            "status": "open",
            "source_engine": "iam",
            "finding_count": iam_total_ch,
            "risk_tier": tier,
        })

    # Mitigation roadmap (UI-expected shape — matches demo data fields)
    roadmap: List[Dict[str, Any]] = []
    if threat_stats["critical"] > 0:
        c = threat_stats["critical"] * 25000
        roadmap.append({
            "action": f"Remediate {threat_stats['critical']} critical threat findings",
            "priority": "P0", "domain": "threats",
            "current_risk": 95, "target_risk": 60,
            "reduction": 37, "cost": f"${c:,}",
            "owner": "Security Team", "due_date": "",
        })
    if iam_stats["critical"] + iam_stats["high"] > 0:
        ch = iam_stats["critical"] + iam_stats["high"]
        c = ch * 10000
        roadmap.append({
            "action": f"Fix {ch} critical/high IAM findings",
            "priority": "P1", "domain": "iam",
            "current_risk": 75, "target_risk": 40,
            "reduction": 47, "cost": f"${c:,}",
            "owner": "IAM Team", "due_date": "",
        })
    if compliance_stats["controls_failed"] > 0:
        c = compliance_stats["controls_failed"] * 5000
        roadmap.append({
            "action": f"Address {compliance_stats['controls_failed']} failing compliance controls",
            "priority": "P1", "domain": "compliance",
            "current_risk": 70, "target_risk": 35,
            "reduction": 50, "cost": f"${c:,}",
            "owner": "GRC Team", "due_date": "",
        })
    if threat_stats["high"] > 0:
        c = threat_stats["high"] * 15000
        roadmap.append({
            "action": f"Investigate {threat_stats['high']} high-severity threat findings",
            "priority": "P2", "domain": "threats",
            "current_risk": 65, "target_risk": 40,
            "reduction": 38, "cost": f"${c:,}",
            "owner": "Security Team", "due_date": "",
        })

    estimated_loss = (
        threat_stats["critical"] * 500_000
        + threat_stats["high"] * 50_000
        + threat_stats.get("medium", 0) * 5_000
    )

    return {
        "risk_score": overall_score,
        "riskScoreChange": 0,
        "accepted_risks": 0,
        "average_loss": estimated_loss,
        "risk_register": risk_register[:10],
        "mitigation_roadmap": roadmap,
        "domain_scores": {
            "iam": iam_score,
            "compliance": compliance_score,
            "threats": threats_score,
            "dataSec": datasec_score,
            "vulnerabilities": vuln_score,
        },
        "threat_stats": {
            "total": threat_stats["total"],
            "critical": threat_stats["critical"],
            "high": threat_stats["high"],
            "medium": threat_stats.get("medium", 0),
            "low": threat_stats.get("low", 0),
        },
        "compliance_stats": {
            "total_controls": compliance_stats["total_controls"],
            "controls_passed": compliance_stats["controls_passed"],
            "controls_failed": compliance_stats["controls_failed"],
            "compliance_pct": compliance_stats["compliance_pct"],
            "frameworks_at_risk": compliance_stats["frameworks_at_risk"],
        },
        "iam_stats": {
            "total": iam_stats["total"],
            "critical": iam_stats["critical"],
            "high": iam_stats["high"],
        },
        "source": "live",
    }


# ---------------------------------------------------------------------------
# Tenant-scoped alias endpoints (UI-friendly: tenant_id as query param)
# ---------------------------------------------------------------------------


def _latest_risk_scan_id(conn, tenant_id: str) -> Optional[str]:
    """Return the most recent completed risk_scan_id for a tenant."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT risk_scan_id::text FROM risk_report
            WHERE tenant_id = %s AND status = 'completed'
            ORDER BY completed_at DESC NULLS LAST LIMIT 1
            """,
            (tenant_id,),
        )
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        cursor.close()


@app.get("/api/v1/risk/dashboard")
async def risk_dashboard(tenant_id: Optional[str] = Query(None)):
    """Aggregate risk dashboard for a tenant (latest scan or live computation)."""
    if not tenant_id:
        return {"risk_score": 0, "accepted_risks": 0, "average_loss": 0, "risk_register": [], "mitigation_roadmap": []}

    # Try to use existing risk scan report first
    conn = get_risk_conn()
    scan_id = _latest_risk_scan_id(conn, tenant_id)
    if scan_id:
        report = await get_report(scan_id)
        total = report.get("total_scenarios", 0) or 1
        critical = report.get("critical_scenarios", 0)
        exposure = report.get("total_exposure_likely", 0)
        risk_score = min(100, int((critical / total) * 100 + (exposure / 1_000_000) * 5))

        top_scenarios = report.get("top_scenarios") or []
        if isinstance(top_scenarios, str):
            import json as _json
            try:
                top_scenarios = _json.loads(top_scenarios)
            except Exception:
                top_scenarios = []

        # Transform top_scenarios into risk_register shape
        risk_register = []
        for idx, s in enumerate(top_scenarios[:10] if isinstance(top_scenarios, list) else []):
            tier = s.get("risk_tier", "medium")
            inherent = {"critical": 95, "high": 75, "medium": 50, "low": 25}.get(tier, 50)
            risk_register.append({
                "id": f"RSK-{idx + 1:03d}",
                "title": s.get("title") or s.get("scenario_type", f"Risk scenario #{idx + 1}"),
                "category": (s.get("source_engine") or "general").replace("_", " ").title(),
                "inherent": inherent,
                "residual": max(10, inherent - 20),
                "owner": "Security Team",
                "status": "open" if tier in ("critical", "high") else "monitoring",
                "scenario_type": s.get("scenario_type", ""),
                "source_engine": s.get("source_engine", ""),
                "expected_loss": s.get("total_exposure_likely", 0),
                "worst_case_loss": s.get("total_exposure_max", 0),
                "risk_tier": tier,
            })

        # Build mitigation_roadmap from top scenarios
        mitigation_roadmap = _build_mitigation_roadmap(top_scenarios, risk_score)

        return {
            "risk_score": risk_score,
            "accepted_risks": 0,
            "average_loss": exposure,
            "risk_register": risk_register,
            "mitigation_roadmap": mitigation_roadmap,
            "source": "risk_scan",
        }

    # No risk scan — compute live from threat + compliance data
    logger.info("No risk scan found for tenant %s — computing live risk score", tenant_id)
    return _compute_live_dashboard(tenant_id)


@app.get("/api/v1/risk/trends")
async def risk_trends(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(30, ge=1, le=365),
):
    """Risk trend data for a tenant (query-param variant of /trends/{tenant_id})."""
    if not tenant_id:
        return {"data": []}
    rows = await get_trends(tenant_id, limit=limit)
    # Normalise for chart: map total_exposure_likely → value, scan_date → date
    data = [
        {
            **r,
            "date": r.get("scan_date"),
            "value": r.get("total_exposure_likely", 0),
        }
        for r in rows
    ]
    return {"data": data}


@app.get("/api/v1/risk/scenarios")
async def risk_scenarios(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """Risk scenarios for a tenant's latest scan."""
    if not tenant_id:
        return {"data": []}
    conn = get_risk_conn()
    scan_id = _latest_risk_scan_id(conn, tenant_id)
    if not scan_id:
        return {"data": []}

    raw = await get_scenarios(scan_id, limit=limit)
    # Normalise to what the UI expects
    data = []
    for r in raw:
        # Convert Decimal to float (psycopg2 returns NUMERIC as Decimal)
        for k, v in list(r.items()):
            if hasattr(v, "as_integer_ratio"):  # Decimal/float duck-type
                r[k] = float(v)
        lef = float(r.get("loss_event_frequency") or 0)
        primary_loss = float(r.get("primary_loss_likely") or 0)
        calc = r.get("calculation_model") or {}
        if isinstance(calc, str):
            import json as _json
            try:
                calc = _json.loads(calc)
            except Exception:
                calc = {}

        data.append({
            **r,
            "scenario_name": r.get("title") or r.get("scenario_type", "Unknown Risk").replace("_", " ").title(),
            "threat_category": (r.get("source_engine") or "cloud").replace("_", " ").title(),
            "probability": round(lef * 100, 1),
            "expected_loss": r.get("total_exposure_likely", 0),
            "worst_case_loss": r.get("total_exposure_max", 0),
            "risk_rating": r.get("risk_tier", "medium"),
            "risk_level": r.get("risk_tier", "medium"),
            "account": r.get("account_id", ""),
            # FAIR model fields the UI needs
            "threat_event_frequency": round(lef, 4),
            "vulnerability": round(calc.get("exposure_factor", lef), 4),
            "loss_magnitude": round(primary_loss, 2),
            "rule_id": r.get("rule_id", ""),
            "resource_uid": r.get("asset_arn", ""),
            "resource_type": r.get("asset_type", ""),
        })
    return {"data": data}


# ---------------------------------------------------------------------------
# Health & Metrics
# ---------------------------------------------------------------------------


@app.get("/api/v1/risk/score")
async def risk_score(tenant_id: Optional[str] = Query(None)):
    """Overall risk score for a tenant."""
    dashboard = await risk_dashboard(tenant_id=tenant_id)
    score = dashboard.get("risk_score", 0)

    # Use per-domain scores from live computation if available
    domain_scores = dashboard.get("domain_scores", None)
    if domain_scores is None:
        domain_scores = {
            "iam": score, "compliance": score, "threats": score,
            "dataSec": score, "vulnerabilities": score,
        }

    prev_score = max(0, score - 3)
    return {
        "tenant_id": tenant_id,
        "score": score,
        "label": "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low",
        "prevScore": prev_score,
        "delta": score - prev_score,
        "status": "Improving" if score <= prev_score else "Degrading",
        "criticalActions": len(dashboard.get("risk_register", [])),
        "domainScores": domain_scores,
    }


@app.get("/api/v1/risk/breakdown")
async def risk_breakdown(tenant_id: Optional[str] = Query(None)):
    """Per-domain risk score breakdown."""
    dashboard = await risk_dashboard(tenant_id=tenant_id)
    domain_scores = dashboard.get("domain_scores", {})
    threat_stats = dashboard.get("threat_stats", {})
    compliance_stats = dashboard.get("compliance_stats", {})
    iam_stats = dashboard.get("iam_stats", {})
    score = dashboard.get("risk_score", 0)

    if domain_scores:
        return {
            "tenant_id": tenant_id,
            "breakdown": [
                {"domain": "Threat Detection", "score": domain_scores.get("threats", 0), "weight": 0.20, "findings": threat_stats.get("total", 0)},
                {"domain": "IAM Security", "score": domain_scores.get("iam", 0), "weight": 0.15, "findings": iam_stats.get("total", 0)},
                {"domain": "Compliance", "score": domain_scores.get("compliance", 0), "weight": 0.15, "findings": compliance_stats.get("controls_failed", 0)},
                {"domain": "Data Security", "score": domain_scores.get("dataSec", 0), "weight": 0.10, "findings": 0},
                {"domain": "Network Security", "score": domain_scores.get("network", score), "weight": 0.10, "findings": 0},
                {"domain": "Container Security", "score": domain_scores.get("container", score), "weight": 0.08, "findings": 0},
                {"domain": "Encryption", "score": domain_scores.get("encryption", score), "weight": 0.07, "findings": 0},
                {"domain": "Database Security", "score": domain_scores.get("database", score), "weight": 0.07, "findings": 0},
                {"domain": "AI Security", "score": domain_scores.get("ai_security", score), "weight": 0.05, "findings": 0},
                {"domain": "Vulnerabilities", "score": domain_scores.get("vulnerabilities", 0), "weight": 0.03, "findings": 0},
            ]
        }

    return {
        "tenant_id": tenant_id,
        "breakdown": [
            {"domain": "Threat Detection", "score": score, "weight": 0.20, "findings": 0},
            {"domain": "IAM Security", "score": score, "weight": 0.15, "findings": 0},
            {"domain": "Compliance", "score": score, "weight": 0.15, "findings": 0},
            {"domain": "Data Security", "score": score, "weight": 0.10, "findings": 0},
            {"domain": "Network Security", "score": score, "weight": 0.10, "findings": 0},
            {"domain": "Container Security", "score": score, "weight": 0.08, "findings": 0},
            {"domain": "Encryption", "score": score, "weight": 0.07, "findings": 0},
            {"domain": "Database Security", "score": score, "weight": 0.07, "findings": 0},
            {"domain": "AI Security", "score": score, "weight": 0.05, "findings": 0},
            {"domain": "Vulnerabilities", "score": score, "weight": 0.03, "findings": 0},
        ]
    }


@app.get("/api/v1/risk/trend")
async def risk_trend(
    tenant_id: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=365),
):
    """Risk trend alias for /api/v1/risk/trends."""
    result = await risk_trends(tenant_id=tenant_id, limit=days)
    return result


@app.get("/api/v1/risk/assets/top")
async def risk_top_assets(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=50),
):
    """Top riskiest assets for a tenant."""
    scenarios = await risk_scenarios(tenant_id=tenant_id, limit=limit)
    assets = []
    for s in scenarios.get("data", [])[:limit]:
        assets.append({
            "resource_uid": s.get("resource_uid", ""),
            "resource_type": s.get("resource_type", ""),
            "risk_score": min(100, int(s.get("expected_loss", 0) / 10000)),
            "account": s.get("account", ""),
            "threat_count": 1,
            "scenario": s.get("scenario_name", ""),
        })
    return {"assets": assets, "total": len(assets)}


# ---------------------------------------------------------------------------
# Unified UI data endpoint
# ---------------------------------------------------------------------------


@app.get("/api/v1/risk/ui-data")
async def risk_ui_data(
    tenant_id: Optional[str] = Query(None, description="Tenant UUID"),
) -> Dict[str, Any]:
    """Consolidated risk data for the frontend dashboard.

    Merges the output of dashboard, scenarios, trends, breakdown, and
    top-assets endpoints into a single payload so the UI can render
    the entire risk page with one call.

    Args:
        tenant_id: Tenant UUID.  If omitted, returns zeroed-out defaults.

    Returns:
        Dict containing risk_score, average_loss, compliance_index,
        risk_register, scenarios, trends, mitigation_roadmap, breakdown,
        top_assets, domain_scores, and source indicator.
    """
    if not tenant_id:
        return {
            "risk_score": 0,
            "average_loss": 0.0,
            "accepted_risks": 0,
            "risk_reduction": 0.0,
            "compliance_index": 0.0,
            "risk_register": [],
            "scenarios": [],
            "trends": [],
            "mitigation_roadmap": [],
            "breakdown": [],
            "top_assets": [],
            "domain_scores": {
                "iam": 0,
                "compliance": 0,
                "threats": 0,
                "dataSec": 0,
                "vulnerabilities": 0,
            },
            "source": "empty",
        }

    try:
        # 1. Dashboard (or live computation) -----------------------------------
        dashboard = await risk_dashboard(tenant_id=tenant_id)
        source = dashboard.get("source", "live")

        risk_score = dashboard.get("risk_score", 0)
        average_loss = dashboard.get("average_loss", 0.0)
        accepted_risks = dashboard.get("accepted_risks", 0)
        risk_register = dashboard.get("risk_register", [])
        mitigation_roadmap = dashboard.get("mitigation_roadmap", [])
        domain_scores = dashboard.get("domain_scores", {
            "iam": risk_score,
            "compliance": risk_score,
            "threats": risk_score,
            "dataSec": risk_score,
            "vulnerabilities": risk_score,
        })

        # Compliance index from live compliance stats (if available)
        compliance_stats = dashboard.get("compliance_stats", {})
        compliance_index = compliance_stats.get("compliance_pct", 0.0)

        # 2. Scenarios (top 20) -------------------------------------------------
        scenarios_resp = await risk_scenarios(tenant_id=tenant_id, limit=20)
        scenarios = scenarios_resp.get("data", [])

        # 3. Trends (last 30 days) ----------------------------------------------
        trends_resp = await risk_trends(tenant_id=tenant_id, limit=30)
        trends_data = trends_resp.get("data", [])
        trends = [
            {
                "date": t.get("date", t.get("scan_date", "")),
                "value": t.get("value", t.get("total_exposure_likely", 0)),
                "critical_scenarios": t.get("critical_scenarios", 0),
            }
            for t in trends_data
        ]

        # 4. Breakdown ----------------------------------------------------------
        breakdown_resp = await risk_breakdown(tenant_id=tenant_id)
        breakdown = breakdown_resp.get("breakdown", [])

        # 5. Top assets ----------------------------------------------------------
        top_assets_resp = await risk_top_assets(tenant_id=tenant_id, limit=10)
        top_assets = top_assets_resp.get("assets", [])

        return {
            "risk_score": risk_score,
            "average_loss": float(average_loss) if average_loss else 0.0,
            "accepted_risks": accepted_risks,
            "risk_reduction": 0.0,
            "compliance_index": compliance_index,
            "risk_register": risk_register,
            "scenarios": scenarios,
            "trends": trends,
            "mitigation_roadmap": mitigation_roadmap,
            "breakdown": breakdown,
            "top_assets": top_assets,
            "domain_scores": domain_scores,
            "source": source,
        }

    except Exception as exc:
        logger.error("risk/ui-data error for tenant %s: %s", tenant_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "ok", "engine": "risk", "port": 8009}


@app.get("/api/v1/health/ready")
async def health_ready():
    try:
        conn = get_risk_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        return {"status": "ready", "engine": "risk"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Not ready: {exc}")


@app.get("/api/v1/metrics")
async def metrics():
    return {
        "engine": "risk",
        "scan_count": _scan_count,
        "scan_errors": _scan_errors,
        "last_scan_duration_ms": _last_scan_duration_ms,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8009)
