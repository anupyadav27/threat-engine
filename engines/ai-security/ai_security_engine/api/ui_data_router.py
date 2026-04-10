"""
Unified UI data endpoint for AI Security Engine.

Provides a single aggregated payload for the CSPM frontend AI Security
page, reading from the AI Security engine's own database tables:
ai_security_report, ai_security_findings, ai_security_inventory.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _get_ai_security_conn():
    """Create a connection to the AI security database."""
    return psycopg2.connect(
        host=os.getenv("AI_SECURITY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("AI_SECURITY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("AI_SECURITY_DB_NAME", "threat_engine_ai_security"),
        user=os.getenv("AI_SECURITY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("AI_SECURITY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    """Resolve 'latest' to the most recent completed scan_run_id for a tenant."""
    cur.execute(
        """SELECT scan_run_id FROM ai_security_report
           WHERE tenant_id = %s AND status = 'completed'
           ORDER BY completed_at DESC LIMIT 1""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return str(row["scan_run_id"]) if row else None


@router.get("/api/v1/ai-security/ui-data")
async def get_ai_security_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="Scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings"),
) -> Dict[str, Any]:
    """Return aggregated AI Security data for the frontend.

    Returns summary, module_breakdown, service_breakdown, inventory,
    shadow_ai findings, findings list, and top_failing_rules.
    """
    conn = None
    try:
        conn = _get_ai_security_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Resolve scan_id
            scan_run_id = (
                _resolve_latest_scan(cur, tenant_id)
                if scan_id == "latest"
                else scan_id
            )
            if not scan_run_id:
                return _empty_response()

            # 2. Report summary
            cur.execute(
                """SELECT * FROM ai_security_report
                   WHERE scan_run_id = %s AND tenant_id = %s
                   LIMIT 1""",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            if not report:
                return _empty_response()

            # 3. AI/ML resource inventory
            cur.execute(
                """SELECT resource_id, resource_uid, resource_name,
                          resource_type, ml_service, model_type, framework,
                          deployment_type, is_public_endpoint, auth_type,
                          has_guardrails, risk_score, account_id, region, provider
                   FROM ai_security_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY risk_score DESC, is_public_endpoint DESC""",
                (scan_run_id, tenant_id),
            )
            inventory = [dict(r) for r in cur.fetchall()]

            # 4. Findings (paginated, ordered by severity)
            cur.execute(
                """SELECT finding_id, rule_id, title, severity, status,
                          category, resource_uid,
                          resource_type, ml_service, detail, remediation,
                          frameworks, mitre_techniques,
                          account_id, region
                   FROM ai_security_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY
                       CASE severity
                           WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                           WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                       END,
                       finding_id
                   LIMIT %s""",
                (scan_run_id, tenant_id, limit),
            )
            findings = []
            for f in cur.fetchall():
                row = dict(f)
                # Parse detail JSON to extract source indicator
                detail_str = row.get("detail") or ""
                detail_obj = {}
                if detail_str:
                    try:
                        import json as _json
                        detail_obj = _json.loads(detail_str) if isinstance(detail_str, str) else detail_str
                    except Exception:
                        detail_obj = {}
                if not isinstance(detail_obj, dict):
                    detail_obj = {}
                row["source"] = detail_obj.get("source", "check")
                findings.append(row)

            # 5. Shadow AI findings (rule_id = 'AI-GOV-002')
            shadow_ai = [f for f in findings if f.get("rule_id") == "AI-GOV-002"]

            # 6. Module breakdown from category_breakdown JSONB
            category_breakdown = report.get("category_breakdown") or {}
            module_breakdown = []
            for module, counts in category_breakdown.items():
                if not isinstance(counts, dict):
                    continue
                p = counts.get("pass", 0)
                f = counts.get("fail", 0)
                total = p + f
                score = round((p / total) * 100, 1) if total > 0 else 0
                module_breakdown.append({
                    "module": module,
                    "total": total,
                    "pass": p,
                    "fail": f,
                    "score": score,
                })
            module_breakdown.sort(key=lambda x: x["fail"], reverse=True)

            # 7. Service breakdown from service_breakdown JSONB
            svc_breakdown_raw = report.get("service_breakdown") or {}
            service_breakdown = []
            for svc, counts in svc_breakdown_raw.items():
                if isinstance(counts, dict):
                    service_breakdown.append({
                        "service": svc,
                        "total": counts.get("total", 0),
                        "pass": counts.get("pass", 0),
                        "fail": counts.get("fail", 0),
                    })
                elif isinstance(counts, int):
                    service_breakdown.append({
                        "service": svc,
                        "total": counts,
                        "pass": 0,
                        "fail": 0,
                    })
            service_breakdown.sort(key=lambda x: x["fail"], reverse=True)

            # 8. Top failing rules from report JSONB
            top_failing_rules = report.get("top_failing_rules") or []

        # -- Assemble response -------------------------------------------------
        return {
            "summary": {
                "scan_run_id": scan_run_id,
                "status": report.get("status", "unknown"),
                "risk_score": float(report.get("risk_score", 0)),
                "total_ml_resources": report.get("total_ml_resources", 0),
                "total_findings": report.get("total_findings", 0),
                "critical_findings": report.get("critical_findings", 0),
                "high_findings": report.get("high_findings", 0),
                "medium_findings": report.get("medium_findings", 0),
                "low_findings": report.get("low_findings", 0),
                "pass_count": report.get("pass_count", 0),
                "fail_count": report.get("fail_count", 0),
                "coverage": {
                    "vpc_isolation_pct": float(report.get("vpc_isolation_pct", 0)),
                    "encryption_rest_pct": float(report.get("encryption_rest_pct", 0)),
                    "encryption_transit_pct": float(report.get("encryption_transit_pct", 0)),
                    "model_card_pct": float(report.get("model_card_pct", 0)),
                    "monitoring_pct": float(report.get("monitoring_pct", 0)),
                    "guardrails_pct": float(report.get("guardrails_pct", 0)),
                },
                "started_at": str(report.get("started_at", "")),
                "completed_at": str(report.get("completed_at", "")),
            },
            "module_breakdown": module_breakdown,
            "service_breakdown": service_breakdown,
            "inventory": inventory,
            "shadow_ai": shadow_ai,
            "findings": findings,
            "top_failing_rules": top_failing_rules,
            "total_findings": report.get("total_findings", 0),
            "scan_id": scan_run_id,
        }

    except Exception:
        logger.exception("Error building AI Security UI data payload")
        return _empty_response()
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _empty_response() -> Dict[str, Any]:
    """Return a zero-valued response when no scan data is available."""
    return {
        "summary": {
            "scan_run_id": None,
            "status": "no_data",
            "risk_score": 0,
            "total_ml_resources": 0,
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "pass_count": 0,
            "fail_count": 0,
            "coverage": {
                "vpc_isolation_pct": 0,
                "encryption_rest_pct": 0,
                "encryption_transit_pct": 0,
                "model_card_pct": 0,
                "monitoring_pct": 0,
                "guardrails_pct": 0,
            },
            "started_at": "",
            "completed_at": "",
        },
        "module_breakdown": [],
        "service_breakdown": [],
        "inventory": [],
        "shadow_ai": [],
        "findings": [],
        "top_failing_rules": [],
        "total_findings": 0,
        "scan_id": None,
    }
