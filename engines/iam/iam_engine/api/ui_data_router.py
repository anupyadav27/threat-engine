"""
Unified UI data endpoint for IAM Security Engine.

Provides a single aggregated payload for the CSPM frontend IAM page,
reading directly from the IAM engine's own database tables
(iam_report, iam_findings) rather than re-querying the Threat DB.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui-data"])

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _get_iam_db_connection() -> psycopg2.extensions.connection:
    """Return a psycopg2 connection to the IAM database.

    Uses IAM_DB_* env vars with fallback to THREAT_DB_* for backwards
    compatibility in environments where only the threat connection is set.
    """
    return psycopg2.connect(
        host=os.getenv("IAM_DB_HOST", os.getenv("THREAT_DB_HOST", "localhost")),
        port=int(os.getenv("IAM_DB_PORT", os.getenv("THREAT_DB_PORT", "5432"))),
        dbname=os.getenv("IAM_DB_NAME", "threat_engine_iam"),
        user=os.getenv("IAM_DB_USER", os.getenv("THREAT_DB_USER", "postgres")),
        password=os.getenv("IAM_DB_PASSWORD", os.getenv("THREAT_DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _resolve_latest_scan_run_id(
    cur: psycopg2.extensions.cursor,
    tenant_id: str,
) -> Optional[str]:
    """Resolve the most recent scan_run_id for a tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: Tenant identifier.

    Returns:
        The latest scan_run_id string, or None if no report exists.
    """
    cur.execute(
        """
        SELECT scan_run_id
        FROM iam_report
        WHERE tenant_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


def _compute_risk_score(
    critical: int,
    high: int,
    medium: int,
    low: int,
    total: int,
) -> int:
    """Compute a 0-100 IAM risk score using weighted severity formula.

    Formula: (critical*10 + high*5 + medium*2 + low*1) / total * 10
    Capped at 100.

    Args:
        critical: Count of critical-severity findings.
        high: Count of high-severity findings.
        medium: Count of medium-severity findings.
        low: Count of low-severity findings.
        total: Total finding count (used as denominator).

    Returns:
        Integer risk score between 0 and 100.
    """
    if total == 0:
        return 0
    raw = (critical * 10 + high * 5 + medium * 2 + low * 1) / total * 10
    return min(int(round(raw)), 100)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get("/api/v1/iam-security/ui-data")
async def get_iam_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="IAM scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings to return"),
) -> Dict[str, Any]:
    """Return aggregated IAM data for the frontend UI page.

    Reads from the IAM engine's own database (iam_report + iam_findings)
    and returns a single payload containing:

    * **summary** -- totals, risk score, breakdowns by module / status / severity
    * **modules** -- list of distinct IAM module names present in findings
    * **findings** -- top *limit* individual findings (default 200)
    * **total_findings** -- overall count (may exceed len(findings))
    * **scan_id** -- the resolved scan_run_id
    """
    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_iam_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # ── 1. Resolve scan_id ──────────────────────────────────────
            scan_run_id: Optional[str] = None
            if scan_id == "latest":
                scan_run_id = _resolve_latest_scan_run_id(cur, tenant_id)
            else:
                scan_run_id = scan_id

            if not scan_run_id:
                return _empty_iam_response()

            # ── 2. Report-level summary ─────────────────────────────────
            cur.execute(
                """
                SELECT total_findings,
                       iam_relevant_findings,
                       critical_findings,
                       high_findings,
                       findings_by_module,
                       findings_by_status,
                       report_data,
                       provider
                FROM iam_report
                WHERE scan_run_id = %s AND tenant_id = %s
                LIMIT 1
                """,
                (scan_run_id, tenant_id),
            )
            report_row = cur.fetchone()

            # ── 3. Severity counts from iam_findings ────────────────────
            cur.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                GROUP BY severity
                """,
                (scan_run_id, tenant_id),
            )
            severity_rows = cur.fetchall()
            by_severity: Dict[str, int] = {}
            for row in severity_rows:
                sev = (row["severity"] or "unknown").lower()
                by_severity[sev] = row["cnt"]

            critical = by_severity.get("critical", 0)
            high = by_severity.get("high", 0)
            medium = by_severity.get("medium", 0)
            low = by_severity.get("low", 0)

            # ── 4. Total findings count ─────────────────────────────────
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                """,
                (scan_run_id, tenant_id),
            )
            total_row = cur.fetchone()
            total_findings = total_row["cnt"] if total_row else 0

            # ── 5. Module breakdown from iam_findings ───────────────────
            # iam_modules is TEXT[] — unnest to count per module
            cur.execute(
                """
                SELECT m AS module, COUNT(*) AS cnt
                FROM iam_findings, unnest(iam_modules) AS m
                WHERE scan_run_id = %s AND tenant_id = %s
                GROUP BY m
                ORDER BY cnt DESC
                """,
                (scan_run_id, tenant_id),
            )
            module_rows = cur.fetchall()
            by_module: Dict[str, int] = {
                row["module"]: row["cnt"] for row in module_rows
            }
            modules_list: List[str] = [row["module"] for row in module_rows]

            # ── 6. Status breakdown from iam_findings ───────────────────
            cur.execute(
                """
                SELECT status, COUNT(*) AS cnt
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                GROUP BY status
                """,
                (scan_run_id, tenant_id),
            )
            status_rows = cur.fetchall()
            by_status: Dict[str, int] = {
                row["status"]: row["cnt"] for row in status_rows
            }

            # Use report-level values when available; fall back to
            # aggregated query values.
            report_by_module = by_module
            report_by_status = by_status
            report_total = total_findings

            if report_row:
                # JSONB columns are auto-deserialized by psycopg2
                fbm = report_row.get("findings_by_module")
                if isinstance(fbm, dict) and fbm:
                    report_by_module = fbm
                fbs = report_row.get("findings_by_status")
                if isinstance(fbs, dict) and fbs:
                    report_by_status = fbs
                rt = report_row.get("total_findings")
                if rt and rt > 0:
                    report_total = rt

            risk_score = _compute_risk_score(
                critical, high, medium, low, total_findings
            )

            # ── 6b. Extract report_data JSONB insights ─────────────────
            report_data_insights = _extract_report_data_insights(report_row)

            # ── 6c. Account breakdown from iam_findings ────────────────
            by_account = _query_by_account(cur, scan_run_id, tenant_id)

            # ── 6d. Region breakdown from iam_findings ─────────────────
            by_region = _query_by_region(cur, scan_run_id, tenant_id)

            # ── 7. Paginated findings list ──────────────────────────────
            cur.execute(
                """
                SELECT finding_id,
                       rule_id,
                       iam_modules,
                       severity,
                       status,
                       resource_type,
                       resource_id,
                       resource_arn,
                       account_id,
                       region,
                       finding_data,
                       resource_uid,
                       account_id AS hierarchy_id,
                       provider
                FROM iam_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    finding_id
                LIMIT %s
                """,
                (scan_run_id, tenant_id, limit),
            )
            finding_rows = cur.fetchall()

            findings: List[Dict[str, Any]] = []
            for f in finding_rows:
                # finding_data is JSONB — already a dict, never json.loads()
                fd = f.get("finding_data")
                if not isinstance(fd, dict):
                    fd = {}
                findings.append({
                    "finding_id": f["finding_id"],
                    "rule_id": f["rule_id"],
                    "iam_modules": f.get("iam_modules") or [],
                    "severity": f["severity"],
                    "status": f["status"],
                    "resource_type": f.get("resource_type"),
                    "resource_id": f.get("resource_id"),
                    "resource_arn": f.get("resource_arn"),
                    "account_id": f.get("account_id"),
                    "region": f.get("region"),
                    "resource_uid": f.get("resource_uid"),
                    "hierarchy_id": f.get("hierarchy_id"),
                    "provider": f.get("provider"),
                    "finding_data": fd,
                })

            # ── 8. Module-grouped finding sections ───────────────────
            # The BFF expects pre-grouped sections for the IAM page tabs.
            roles = _query_findings_by_module(cur, scan_run_id, tenant_id, "roles", limit)
            access_keys = _query_findings_by_module(cur, scan_run_id, tenant_id, "access_keys", limit)
            privilege_escalation = _query_findings_by_module(cur, scan_run_id, tenant_id, "privilege_escalation", limit)
            service_accounts = _query_service_account_findings(cur, scan_run_id, tenant_id, limit)

        return {
            "summary": {
                "total_findings": report_total,
                "risk_score": risk_score,
                "by_module": report_by_module,
                "by_status": report_by_status,
                "by_severity": by_severity,
                "by_account": by_account,
                "by_region": by_region,
                "report_insights": report_data_insights,
            },
            "modules": modules_list,
            "findings": findings,
            "roles": roles,
            "access_keys": access_keys,
            "privilege_escalation": privilege_escalation,
            "service_accounts": service_accounts,
            "total_findings": report_total,
            "scan_id": scan_run_id,
        }

    except Exception:
        logger.exception("Error building IAM UI data payload")
        return _empty_iam_response()
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Additional query helpers
# ---------------------------------------------------------------------------

def _extract_report_data_insights(
    report_row: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Extract useful summary fields from iam_report.report_data JSONB.

    The report_data column may contain engine-computed insights such as
    overall risk_score, policy analysis summaries, identity counts, and
    other aggregate metrics produced during the IAM scan.

    IMPORTANT: psycopg2 auto-deserializes JSONB -- never call json.loads().

    Args:
        report_row: The iam_report row dict (may be None).

    Returns:
        A dict of extracted insight fields. Empty dict if report_data is
        absent or not a dict.
    """
    if not report_row:
        return {}

    report_data = report_row.get("report_data")
    if not isinstance(report_data, dict):
        return {}

    # Extract commonly-written keys from the IAM engine's report_data.
    # Only include keys that actually have values.
    insights: Dict[str, Any] = {}

    # Numeric summaries
    for key in (
        "risk_score",
        "critical_findings_count",
        "high_findings_count",
        "total_identities",
        "total_policies",
        "overprivileged_identities",
        "unused_credentials_count",
        "mfa_disabled_count",
        "admin_access_count",
        "cross_account_roles_count",
        "service_accounts_count",
        "inactive_users_count",
        "password_policy_score",
    ):
        val = report_data.get(key)
        if val is not None:
            insights[key] = val

    # Dict/list summaries (pass through as-is since JSONB is already deserialized)
    for key in (
        "policy_analysis",
        "identity_summary",
        "access_key_summary",
        "permission_boundaries",
        "compliance_gaps",
    ):
        val = report_data.get(key)
        if isinstance(val, (dict, list)) and val:
            insights[key] = val

    return insights


def _query_by_account(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Aggregate IAM findings by account_id with severity breakdown.

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: IAM scan identifier.
        tenant_id: Tenant identifier.

    Returns:
        List of account breakdown dicts sorted by count descending.
    """
    try:
        cur.execute(
            """
            SELECT account_id,
                   COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE severity = 'high') AS high,
                   COUNT(*) FILTER (WHERE severity = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE severity = 'low') AS low
            FROM iam_findings
            WHERE scan_run_id = %s AND tenant_id = %s
            GROUP BY account_id
            ORDER BY count DESC
            """,
            (scan_run_id, tenant_id),
        )
        return [
            {
                "account_id": row["account_id"] or "unknown",
                "count": row["count"],
                "critical": row["critical"],
                "high": row["high"],
                "medium": row["medium"],
                "low": row["low"],
            }
            for row in cur.fetchall()
        ]
    except Exception:
        logger.warning("IAM by_account query failed", exc_info=True)
        return []


def _empty_iam_response() -> Dict[str, Any]:
    """Return a valid but empty IAM UI data response."""
    return {
        "summary": {
            "total_findings": 0,
            "risk_score": 0,
            "by_module": {},
            "by_status": {},
            "by_severity": {},
            "by_account": [],
            "by_region": [],
            "report_insights": {},
        },
        "modules": [],
        "findings": [],
        "roles": [],
        "access_keys": [],
        "privilege_escalation": [],
        "service_accounts": [],
        "total_findings": 0,
        "scan_id": None,
    }


def _finding_row_to_dict(f: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a finding DB row to a serializable dict.

    Shared by the main findings list and the module-grouped sections.
    """
    fd = f.get("finding_data")
    if not isinstance(fd, dict):
        fd = {}
    return {
        "finding_id": f["finding_id"],
        "rule_id": f["rule_id"],
        "iam_modules": f.get("iam_modules") or [],
        "severity": f["severity"],
        "status": f["status"],
        "resource_type": f.get("resource_type"),
        "resource_id": f.get("resource_id"),
        "resource_arn": f.get("resource_arn"),
        "account_id": f.get("account_id"),
        "region": f.get("region"),
        "resource_uid": f.get("resource_uid"),
        "hierarchy_id": f.get("hierarchy_id"),
        "provider": f.get("provider"),
        "finding_data": fd,
    }


def _query_findings_by_module(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
    module_name: str,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return findings where iam_modules[] contains *module_name*.

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: IAM scan identifier.
        tenant_id: Tenant identifier.
        module_name: Module name to filter on (e.g. 'roles', 'access_keys').
        limit: Max findings to return.

    Returns:
        List of finding dicts sorted by severity.
    """
    try:
        cur.execute(
            """
            SELECT finding_id, rule_id, iam_modules, severity, status,
                   resource_type, resource_id, resource_arn, account_id,
                   region, finding_data, resource_uid, account_id AS hierarchy_id, provider
            FROM iam_findings
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND %s = ANY(iam_modules)
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                finding_id
            LIMIT %s
            """,
            (scan_run_id, tenant_id, module_name, limit),
        )
        return [_finding_row_to_dict(row) for row in cur.fetchall()]
    except Exception:
        logger.warning(
            "IAM module query failed for %s", module_name, exc_info=True
        )
        return []


def _query_service_account_findings(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return findings for service accounts.

    Service accounts are identified either by an 'service_accounts' entry in
    iam_modules OR by finding_data->>'identity_type' = 'service' /
    finding_data->>'identity_name' matching service patterns (lambda, ecs, etc.).

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: IAM scan identifier.
        tenant_id: Tenant identifier.
        limit: Max findings to return.

    Returns:
        List of finding dicts sorted by severity.
    """
    try:
        cur.execute(
            """
            SELECT finding_id, rule_id, iam_modules, severity, status,
                   resource_type, resource_id, resource_arn, account_id,
                   region, finding_data, resource_uid, account_id AS hierarchy_id, provider
            FROM iam_findings
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND (
                  'service_accounts' = ANY(iam_modules)
                  OR finding_data->>'identity_type' = 'service'
                  OR resource_type ILIKE '%%role%%'
              )
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                finding_id
            LIMIT %s
            """,
            (scan_run_id, tenant_id, limit),
        )
        return [_finding_row_to_dict(row) for row in cur.fetchall()]
    except Exception:
        logger.warning("IAM service_accounts query failed", exc_info=True)
        return []


def _query_by_region(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Aggregate IAM findings by region with severity breakdown.

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: IAM scan identifier.
        tenant_id: Tenant identifier.

    Returns:
        List of region breakdown dicts sorted by count descending.
    """
    try:
        cur.execute(
            """
            SELECT region,
                   COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE severity = 'high') AS high,
                   COUNT(*) FILTER (WHERE severity = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE severity = 'low') AS low
            FROM iam_findings
            WHERE scan_run_id = %s AND tenant_id = %s
              AND region IS NOT NULL
            GROUP BY region
            ORDER BY count DESC
            """,
            (scan_run_id, tenant_id),
        )
        return [
            {
                "region": row["region"],
                "count": row["count"],
                "critical": row["critical"],
                "high": row["high"],
                "medium": row["medium"],
                "low": row["low"],
            }
            for row in cur.fetchall()
        ]
    except Exception:
        logger.warning("IAM by_region query failed", exc_info=True)
        return []
