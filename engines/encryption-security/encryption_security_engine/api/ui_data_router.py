"""
Unified UI data endpoint for Encryption Security Engine.

Provides a single aggregated payload for the CSPM frontend Encryption
page, reading from the Encryption engine's own database tables.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])


def _get_encryption_conn():
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _query_scan_trend(cur, tenant_id: str) -> list:
    """Return last 8 encryption scan summaries for trend charts (oldest-first)."""
    try:
        cur.execute(
            """
            SELECT
                to_char(r.generated_at, 'Mon DD')     AS date,
                COALESCE(r.total_findings, 0)         AS total,
                COALESCE(r.critical_findings, 0)      AS critical,
                COALESCE(r.high_findings, 0)          AS high,
                COALESCE(r.medium_findings, 0)        AS medium,
                COALESCE(r.low_findings, 0)           AS low,
                COALESCE(r.posture_score, 0)          AS pass_rate,
                COALESCE(r.unencrypted_resources, 0)  AS unencrypted,
                (SELECT COUNT(*)
                 FROM encryption_cert_inventory ec
                 WHERE ec.scan_run_id = r.scan_run_id
                   AND ec.tenant_id   = r.tenant_id
                   AND ec.days_until_expiry <= 30)    AS expiring_certs
            FROM encryption_report r
            WHERE r.tenant_id = %s AND r.status = 'completed'
            ORDER BY r.generated_at DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("encryption scan_trend query failed", exc_info=True)
        return []


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    cur.execute(
        """SELECT scan_run_id FROM encryption_report
           WHERE tenant_id = %s AND status = 'completed'
           ORDER BY generated_at DESC LIMIT 1""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


@router.get("/api/v1/encryption/ui-data")
async def get_encryption_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="Scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings"),
) -> Dict[str, Any]:
    """Return aggregated Encryption Security data for the frontend.

    Returns: summary, coverage_heatmap, key_inventory, cert_inventory,
    secrets_inventory, findings, posture_score.
    """
    conn = None
    try:
        conn = _get_encryption_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Resolve scan_id
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return _empty_response()

            # 2. Report summary
            cur.execute(
                """SELECT * FROM encryption_report
                   WHERE scan_run_id = %s AND tenant_id = %s LIMIT 1""",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            if not report:
                return _empty_response()

            # 3. Key inventory
            cur.execute(
                """SELECT key_arn, key_id, key_alias, key_state, key_manager,
                          key_spec, origin, multi_region, enabled,
                          rotation_enabled, rotation_interval_days, creation_date,
                          grant_count, cross_account_access, dependent_resource_count,
                          account_id, region, provider
                   FROM encryption_key_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY key_manager DESC, key_state""",
                (scan_run_id, tenant_id),
            )
            key_inventory = [dict(r) for r in cur.fetchall()]

            # 4. Cert inventory
            cur.execute(
                """SELECT cert_arn, domain_name, cert_status, cert_type,
                          key_algorithm, issuer, not_after, days_until_expiry,
                          renewal_eligibility, in_use, is_wildcard, is_self_signed,
                          account_id, region, provider
                   FROM encryption_cert_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY days_until_expiry ASC NULLS LAST""",
                (scan_run_id, tenant_id),
            )
            cert_inventory = [dict(r) for r in cur.fetchall()]

            # 5. Secrets inventory
            cur.execute(
                """SELECT secret_arn, secret_name, kms_key_id,
                          rotation_enabled, rotation_interval_days,
                          last_rotated_date, days_since_rotation,
                          account_id, region, provider
                   FROM encryption_secrets_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                   ORDER BY rotation_enabled ASC, days_since_rotation DESC NULLS LAST""",
                (scan_run_id, tenant_id),
            )
            secrets_inventory = [dict(r) for r in cur.fetchall()]

            # 6. Findings (paginated)
            cur.execute(
                """SELECT finding_id, resource_uid, resource_type,
                          encryption_domain, encryption_status, key_type,
                          algorithm, rotation_compliant, transit_enforced,
                          severity, status, rule_id, finding_data,
                          account_id, region
                   FROM encryption_findings
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
                fd = f.get("finding_data")
                if not isinstance(fd, dict):
                    fd = {}
                row = {**dict(f), "finding_data": fd}
                # Unpack rule metadata from finding_data JSONB (not in SELECT columns)
                row.setdefault("title",                 fd.get("title") or fd.get("rule_name") or f.get("rule_id", ""))
                row.setdefault("description",           fd.get("description") or fd.get("rationale") or "")
                row.setdefault("remediation",           fd.get("remediation") or "")
                row.setdefault("posture_category",      fd.get("posture_category") or "")
                row.setdefault("domain",                fd.get("domain") or "")
                row.setdefault("risk_score",            fd.get("risk_score"))
                row.setdefault("compliance_frameworks", fd.get("compliance_frameworks") or [])
                row.setdefault("mitre_tactics",         fd.get("mitre_tactics") or [])
                row.setdefault("mitre_techniques",      fd.get("mitre_techniques") or [])
                row.setdefault("checked_fields",        fd.get("checked_fields"))
                row.setdefault("actual_values",         fd.get("actual_values"))
                row.setdefault("source",                fd.get("source", "check"))
                findings.append(row)

            # 7. Domain breakdown
            cur.execute(
                """SELECT encryption_domain, COUNT(*) as count,
                          COUNT(*) FILTER (WHERE status = 'FAIL') as fail_count
                   FROM encryption_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                   GROUP BY encryption_domain ORDER BY fail_count DESC""",
                (scan_run_id, tenant_id),
            )
            domain_breakdown = [dict(r) for r in cur.fetchall()]

            # 8. Expiring certs summary
            expiring_7d = sum(1 for c in cert_inventory if c.get("days_until_expiry") is not None and c["days_until_expiry"] <= 7)
            expiring_30d = sum(1 for c in cert_inventory if c.get("days_until_expiry") is not None and c["days_until_expiry"] <= 30)

            # 9. Scan trend (last 8 scans, oldest-first)
            scan_trend = _query_scan_trend(cur, tenant_id)

        return {
            "summary": {
                "posture_score": report.get("posture_score", 0),
                "coverage_score": report.get("coverage_score", 0),
                "rotation_score": report.get("rotation_score", 0),
                "algorithm_score": report.get("algorithm_score", 0),
                "transit_score": report.get("transit_score", 0),
                "total_resources": report.get("total_resources", 0),
                "encrypted_resources": report.get("encrypted_resources", 0),
                "unencrypted_resources": report.get("unencrypted_resources", 0),
                "total_keys": report.get("total_keys", 0),
                "total_certificates": report.get("total_certificates", 0),
                "total_secrets": report.get("total_secrets", 0),
                "total_findings": report.get("total_findings", 0),
                "critical_findings": report.get("critical_findings", 0),
                "high_findings": report.get("high_findings", 0),
                "medium_findings": report.get("medium_findings", 0),
                "low_findings": report.get("low_findings", 0),
                "expiring_certs_7d": expiring_7d,
                "expiring_certs_30d": expiring_30d,
            },
            "coverage_heatmap": report.get("coverage_by_service") or {},
            "domain_breakdown": domain_breakdown,
            "key_inventory": key_inventory,
            "cert_inventory": cert_inventory,
            "secrets_inventory": secrets_inventory,
            "findings": findings,
            "scan_trend": scan_trend,
            "total_findings": report.get("total_findings", 0),
            "scan_id": scan_run_id,
        }

    except Exception:
        logger.exception("Error building Encryption UI data payload")
        return _empty_response()
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _empty_response() -> Dict[str, Any]:
    return {
        "summary": {
            "posture_score": 0, "coverage_score": 0, "rotation_score": 0,
            "algorithm_score": 0, "transit_score": 0,
            "total_resources": 0, "encrypted_resources": 0, "unencrypted_resources": 0,
            "total_keys": 0, "total_certificates": 0, "total_secrets": 0,
            "total_findings": 0, "critical_findings": 0, "high_findings": 0,
            "medium_findings": 0, "low_findings": 0,
            "expiring_certs_7d": 0, "expiring_certs_30d": 0,
        },
        "coverage_heatmap": {},
        "domain_breakdown": [],
        "key_inventory": [],
        "cert_inventory": [],
        "secrets_inventory": [],
        "findings": [],
        "total_findings": 0,
        "scan_id": None,
    }
