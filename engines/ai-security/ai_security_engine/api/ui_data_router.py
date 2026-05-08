"""
Unified UI data endpoint for AI Security Engine.

Provides a single aggregated payload for the CSPM frontend AI Security
page, reading from the AI Security engine's own database tables:
ai_security_report, ai_security_findings, ai_security_inventory.
"""

import logging
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Depends, Query

from engine_common.db_connections import get_ai_security_conn

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
# TODO: ai_security:read is not in the 23-key seed; using threat:read as fallback.
# File RBAC-02 amendment to add ai_security:read when product confirms the key name.
try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential_ref/credential_type for non-platform-admin callers."""
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and hasattr(auth, "level") and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        stripped.append(r)
    return stripped


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    """Resolve 'latest' to the most recent completed scan_run_id for a tenant.

    Skips orphaned reports (completed status but no backing findings rows).
    Falls back to ai_security_findings directly when no valid report exists.
    """
    cur.execute(
        """
        SELECT r.scan_run_id FROM ai_security_report r
        WHERE r.tenant_id = %s AND r.status = 'completed'
          AND EXISTS (
              SELECT 1 FROM ai_security_findings f
              WHERE f.scan_run_id = r.scan_run_id AND f.tenant_id = r.tenant_id
          )
        ORDER BY r.completed_at DESC NULLS LAST LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    if row:
        return str(row["scan_run_id"])
    # Fallback: find latest scan_run_id directly from findings table
    cur.execute(
        """
        SELECT scan_run_id, COUNT(*) AS cnt
        FROM ai_security_findings
        WHERE tenant_id = %s
        GROUP BY scan_run_id
        ORDER BY MAX(last_seen_at) DESC NULLS LAST, cnt DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    return str(row["scan_run_id"]) if row else None


@router.get("/api/v1/ai-security/ui-data")
async def get_ai_security_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="Scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings"),
    auth: Any = Depends(require_permission("threat:read") if _AUTH_AVAILABLE else (lambda: None)),
) -> Dict[str, Any]:
    """Return aggregated AI Security data for the frontend.

    Returns summary, module_breakdown, service_breakdown, inventory,
    shadow_ai findings, findings list, and top_failing_rules.
    """
    conn = None
    try:
        conn = get_ai_security_conn()
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

            # 9. Coverage — computed live from ai_security_findings
            #    All queries are scoped to tenant_id + scan_run_id (parameterized).
            coverage = _compute_coverage(cur, scan_run_id, tenant_id)

        # -- Strip sensitive fields before assembling response -----------------
        findings = _strip_sensitive_fields(findings, auth)
        inventory = _strip_sensitive_fields(inventory, auth)

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
                "coverage": coverage,
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


def _compute_coverage(cur: Any, scan_run_id: str, tenant_id: str) -> Dict[str, int]:
    """Compute coverage percentages live from ai_security_findings.

    All six keys are derived from pillar and status columns.
    Every query is scoped to both tenant_id and scan_run_id (parameterized).

    Args:
        cur: psycopg2 cursor (RealDictCursor).
        scan_run_id: The scan run identifier.
        tenant_id: Tenant identifier — included in every WHERE clause.

    Returns:
        Dict with six integer coverage percentages, each clamped to 0-100.
    """
    def _pct(numerator: int, denominator: int) -> int:
        """Safe integer percentage, clamped to 0-100."""
        if denominator <= 0:
            return 0
        return max(0, min(100, round((numerator / denominator) * 100)))

    # Total findings for this scan (denominator for vpc/encryption/model_card/vpc_isolation)
    cur.execute(
        """SELECT COUNT(*) AS total
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s""",
        (scan_run_id, tenant_id),
    )
    total = int((cur.fetchone() or {}).get("total") or 0)

    # encryption_rest_pct — model_security pillar PASS / total
    cur.execute(
        """SELECT COUNT(*) AS n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'model_security' AND status = 'PASS'""",
        (scan_run_id, tenant_id),
    )
    enc_rest_pass = int((cur.fetchone() or {}).get("n") or 0)

    # encryption_transit_pct — inference_security pillar PASS / total
    cur.execute(
        """SELECT COUNT(*) AS n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'inference_security' AND status = 'PASS'""",
        (scan_run_id, tenant_id),
    )
    enc_transit_pass = int((cur.fetchone() or {}).get("n") or 0)

    # model_card_pct — ai_governance pillar PASS / total
    cur.execute(
        """SELECT COUNT(*) AS n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'ai_governance' AND status = 'PASS'""",
        (scan_run_id, tenant_id),
    )
    model_card_pass = int((cur.fetchone() or {}).get("n") or 0)

    # monitoring_pct — 100 if any ai_governance finding exists, else 0
    cur.execute(
        """SELECT COUNT(*) AS n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'ai_governance'""",
        (scan_run_id, tenant_id),
    )
    monitoring_present = int((cur.fetchone() or {}).get("n") or 0)

    # guardrails_pct — inference_security PASS / inference_security total
    cur.execute(
        """SELECT
               COUNT(*) FILTER (WHERE status = 'PASS') AS pass_n,
               COUNT(*) AS total_n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'inference_security'""",
        (scan_run_id, tenant_id),
    )
    row = cur.fetchone() or {}
    guardrails_pass  = int(row.get("pass_n") or 0)
    guardrails_total = int(row.get("total_n") or 0)

    # vpc_isolation_pct — supply_chain pillar PASS / total
    cur.execute(
        """SELECT COUNT(*) AS n
           FROM ai_security_findings
           WHERE scan_run_id = %s AND tenant_id = %s
             AND pillar = 'supply_chain' AND status = 'PASS'""",
        (scan_run_id, tenant_id),
    )
    vpc_pass = int((cur.fetchone() or {}).get("n") or 0)

    return {
        "vpc_isolation_pct":      _pct(vpc_pass, total),
        "encryption_rest_pct":    _pct(enc_rest_pass, total),
        "encryption_transit_pct": _pct(enc_transit_pass, total),
        "model_card_pct":         _pct(model_card_pass, total),
        "monitoring_pct":         100 if monitoring_present > 0 else 0,
        "guardrails_pct":         _pct(guardrails_pass, guardrails_total),
    }


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
