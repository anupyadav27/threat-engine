"""
Unified UI data endpoint for Data Security Engine.

Provides a single aggregated payload for the CSPM frontend Data Security
page, reading directly from the DataSec engine's own database tables
(datasec_report, datasec_findings, datasec_data_store_services) rather
than re-querying the Threat DB.
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

def _get_datasec_db_connection() -> psycopg2.extensions.connection:
    """Return a psycopg2 connection to the DataSec database.

    Uses DATASEC_DB_* env vars with fallback to THREAT_DB_* for backwards
    compatibility in environments where only the threat connection is set.
    """
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", os.getenv("THREAT_DB_HOST", "localhost")),
        port=int(os.getenv("DATASEC_DB_PORT", os.getenv("THREAT_DB_PORT", "5432"))),
        dbname=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", os.getenv("THREAT_DB_USER", "postgres")),
        password=os.getenv("DATASEC_DB_PASSWORD", os.getenv("THREAT_DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _resolve_latest_datasec_scan_id(
    cur: psycopg2.extensions.cursor,
    tenant_id: str,
) -> Optional[str]:
    """Resolve the most recent datasec_scan_id for a tenant.

    Args:
        cur: Database cursor (RealDictCursor).
        tenant_id: Tenant identifier.

    Returns:
        The latest datasec_scan_id string, or None if no report exists.
    """
    cur.execute(
        """
        SELECT datasec_scan_id
        FROM datasec_report
        WHERE tenant_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["datasec_scan_id"] if row else None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get("/api/v1/data-security/ui-data")
async def get_datasec_ui_data(
    tenant_id: str = Query(..., description="Tenant ID"),
    scan_id: str = Query(default="latest", description="DataSec scan ID or 'latest'"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max findings to return"),
) -> Dict[str, Any]:
    """Return aggregated Data Security data for the frontend UI page.

    Reads from the DataSec engine's own database (datasec_report,
    datasec_findings, datasec_data_store_services) and returns a single
    payload containing:

    * **summary** -- totals, percentages, breakdowns by module /
      classification / sensitivity
    * **catalog** -- data store resources derived from findings
    * **findings** -- top *limit* individual findings (default 200)
    * **total_findings** -- overall count (may exceed len(findings))
    * **scan_id** -- the resolved datasec_scan_id
    """
    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_datasec_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # ── 1. Resolve scan_id ──────────────────────────────────────
            datasec_scan_id: Optional[str] = None
            if scan_id == "latest":
                datasec_scan_id = _resolve_latest_datasec_scan_id(cur, tenant_id)
            else:
                datasec_scan_id = scan_id

            if not datasec_scan_id:
                return _empty_response()

            # ── 2. Report-level summary ─────────────────────────────────
            cur.execute(
                """
                SELECT total_findings,
                       datasec_relevant_findings,
                       classified_resources,
                       total_data_stores,
                       findings_by_module,
                       classification_summary,
                       residency_summary,
                       report_data,
                       provider
                FROM datasec_report
                WHERE datasec_scan_id = %s AND tenant_id = %s
                LIMIT 1
                """,
                (datasec_scan_id, tenant_id),
            )
            report_row = cur.fetchone()

            # ── 3. Total findings count ─────────────────────────────────
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM datasec_findings
                WHERE datasec_scan_id = %s AND tenant_id = %s
                """,
                (datasec_scan_id, tenant_id),
            )
            total_row = cur.fetchone()
            total_findings = total_row["cnt"] if total_row else 0

            # ── 4. Module breakdown from datasec_findings ───────────────
            # datasec_modules is TEXT[] — unnest to count per module
            cur.execute(
                """
                SELECT m AS module, COUNT(*) AS cnt
                FROM datasec_findings, unnest(datasec_modules) AS m
                WHERE datasec_scan_id = %s AND tenant_id = %s
                GROUP BY m
                ORDER BY cnt DESC
                """,
                (datasec_scan_id, tenant_id),
            )
            module_rows = cur.fetchall()
            by_module: Dict[str, int] = {
                row["module"]: row["cnt"] for row in module_rows
            }

            # ── 5. Classification breakdown ─────────────────────────────
            # data_classification is TEXT[] on datasec_findings
            cur.execute(
                """
                SELECT c AS classification, COUNT(DISTINCT resource_uid) AS cnt
                FROM datasec_findings, unnest(data_classification) AS c
                WHERE datasec_scan_id = %s AND tenant_id = %s
                GROUP BY c
                ORDER BY cnt DESC
                """,
                (datasec_scan_id, tenant_id),
            )
            class_rows = cur.fetchall()
            by_classification: Dict[str, int] = {
                row["classification"]: row["cnt"] for row in class_rows
            }

            # ── 6. Sensitive-exposed count ──────────────────────────────
            # Resources with sensitivity_score > 70 AND status = 'FAIL'
            cur.execute(
                """
                SELECT COUNT(DISTINCT resource_uid) AS cnt
                FROM datasec_findings
                WHERE datasec_scan_id = %s
                  AND tenant_id = %s
                  AND sensitivity_score > 70
                  AND status = 'FAIL'
                """,
                (datasec_scan_id, tenant_id),
            )
            sensitive_row = cur.fetchone()
            sensitive_exposed = sensitive_row["cnt"] if sensitive_row else 0

            # ── 7. Encrypted / classified percentages ───────────────────
            total_data_stores = 0
            encrypted_pct = 0.0
            classified_pct = 0.0

            if report_row:
                total_data_stores = report_row.get("total_data_stores") or 0

                cls_summary = report_row.get("classification_summary")
                if isinstance(cls_summary, dict):
                    classified_resources = cls_summary.get(
                        "classified_resources",
                        report_row.get("classified_resources", 0),
                    )
                    if total_data_stores > 0:
                        classified_pct = round(
                            classified_resources / total_data_stores * 100, 1
                        )

                # Encrypted percentage: look in report_data or derive
                # from findings_by_module (encryption pass vs total)
                rpt_data = report_row.get("report_data")
                if isinstance(rpt_data, dict):
                    enc = rpt_data.get("encrypted_pct")
                    if enc is not None:
                        encrypted_pct = float(enc)

                # Fallback: compute from encryption module findings
                if encrypted_pct == 0.0:
                    encrypted_pct = _compute_encrypted_pct(
                        cur, datasec_scan_id, tenant_id
                    )

                # Use report-level values when available
                fbm = report_row.get("findings_by_module")
                if isinstance(fbm, dict) and fbm:
                    by_module = fbm

                rt = report_row.get("total_findings")
                if rt and rt > 0:
                    total_findings = rt

            # ── 8a. Residency summary ──────────────────────────────────
            # Prefer report-level residency_summary JSONB; fall back to
            # region breakdown computed from datasec_findings.
            residency = {}
            if report_row:
                rs = report_row.get("residency_summary")
                if isinstance(rs, dict) and rs:
                    residency = rs

            # Always compute live region breakdown from findings
            by_region = _query_region_breakdown(cur, datasec_scan_id, tenant_id)

            # If report-level residency_summary was empty, populate from
            # live region counts
            if not residency and by_region:
                residency = {"by_region": by_region}
            elif residency and by_region:
                # Merge live counts under a separate key so UI has both
                residency["by_region"] = by_region

            # ── 8b. Build data-store catalog ────────────────────────────
            catalog = _build_catalog(cur, datasec_scan_id, tenant_id)

            # ── 9a. Module-grouped sections for BFF ─────────────────────
            classifications = _query_findings_by_module(cur, datasec_scan_id, tenant_id, "classification", limit)
            dlp_violations = _query_findings_by_module(cur, datasec_scan_id, tenant_id, "dlp", limit)
            encryption_status = _query_findings_by_module(cur, datasec_scan_id, tenant_id, "encryption", limit)

            # ── 9. Paginated findings list ──────────────────────────────
            cur.execute(
                """
                SELECT finding_id,
                       rule_id,
                       datasec_modules,
                       severity,
                       status,
                       resource_type,
                       resource_id,
                       resource_arn,
                       account_id,
                       region,
                       data_classification,
                       sensitivity_score,
                       finding_data,
                       resource_uid
                FROM datasec_findings
                WHERE datasec_scan_id = %s AND tenant_id = %s
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    sensitivity_score DESC NULLS LAST,
                    finding_id
                LIMIT %s
                """,
                (datasec_scan_id, tenant_id, limit),
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
                    "datasec_modules": f.get("datasec_modules") or [],
                    "severity": f["severity"],
                    "status": f["status"],
                    "resource_type": f.get("resource_type"),
                    "resource_id": f.get("resource_id"),
                    "resource_arn": f.get("resource_arn"),
                    "account_id": f.get("account_id"),
                    "region": f.get("region"),
                    "data_classification": f.get("data_classification") or [],
                    "sensitivity_score": f.get("sensitivity_score"),
                    "resource_uid": f.get("resource_uid"),
                    "finding_data": fd,
                })

        return {
            "summary": {
                "total_findings": total_findings,
                "total_stores": total_data_stores,
                "by_module": by_module,
                "by_classification": by_classification,
                "sensitive_exposed": sensitive_exposed,
                "encrypted_pct": encrypted_pct,
                "classified_pct": classified_pct,
                "residency": residency,
                "by_region": by_region,
            },
            "catalog": catalog,
            "classifications": classifications,
            "dlp_violations": dlp_violations,
            "encryption_status": encryption_status,
            "residency": by_region,
            "activity": [],
            "lineage": {},
            "findings": findings,
            "total_findings": total_findings,
            "scan_id": datasec_scan_id,
        }

    except Exception:
        logger.exception("Error building DataSec UI data payload")
        return _empty_response()
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _empty_response() -> Dict[str, Any]:
    """Return a valid but empty UI data response."""
    return {
        "summary": {
            "total_findings": 0,
            "total_stores": 0,
            "by_module": {},
            "by_classification": {},
            "sensitive_exposed": 0,
            "encrypted_pct": 0.0,
            "classified_pct": 0.0,
            "residency": {},
            "by_region": [],
        },
        "catalog": [],
        "classifications": [],
        "dlp_violations": [],
        "encryption_status": [],
        "residency": [],
        "activity": [],
        "lineage": {},
        "findings": [],
        "total_findings": 0,
        "scan_id": None,
    }


def _query_findings_by_module(
    cur: psycopg2.extensions.cursor,
    datasec_scan_id: str,
    tenant_id: str,
    module_name: str,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return findings where datasec_modules[] contains *module_name*.

    Args:
        cur: Database cursor (RealDictCursor).
        datasec_scan_id: DataSec scan identifier.
        tenant_id: Tenant identifier.
        module_name: Module pattern to filter on (e.g. 'classification', 'dlp', 'encryption').
        limit: Max findings to return.

    Returns:
        List of finding dicts sorted by severity.
    """
    try:
        # Use ILIKE ANY to match partial module names (e.g. 'data_protection_encryption' matches 'encryption')
        cur.execute(
            """
            SELECT finding_id, rule_id, datasec_modules, severity, status,
                   resource_type, resource_id, resource_arn, account_id,
                   region, data_classification, sensitivity_score,
                   finding_data, resource_uid
            FROM datasec_findings
            WHERE datasec_scan_id = %s
              AND tenant_id = %s
              AND EXISTS (
                  SELECT 1 FROM unnest(datasec_modules) AS m
                  WHERE m ILIKE %s
              )
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                sensitivity_score DESC NULLS LAST,
                finding_id
            LIMIT %s
            """,
            (datasec_scan_id, tenant_id, f"%{module_name}%", limit),
        )
        rows = cur.fetchall()
        result: List[Dict[str, Any]] = []
        for f in rows:
            fd = f.get("finding_data")
            if not isinstance(fd, dict):
                fd = {}
            result.append({
                "finding_id": f["finding_id"],
                "rule_id": f["rule_id"],
                "datasec_modules": f.get("datasec_modules") or [],
                "severity": f["severity"],
                "status": f["status"],
                "resource_type": f.get("resource_type"),
                "resource_id": f.get("resource_id"),
                "resource_arn": f.get("resource_arn"),
                "account_id": f.get("account_id"),
                "region": f.get("region"),
                "data_classification": f.get("data_classification") or [],
                "sensitivity_score": f.get("sensitivity_score"),
                "resource_uid": f.get("resource_uid"),
                "finding_data": fd,
            })
        return result
    except Exception:
        logger.warning(
            "DataSec module query failed for %s", module_name, exc_info=True
        )
        return []


def _compute_encrypted_pct(
    cur: psycopg2.extensions.cursor,
    datasec_scan_id: str,
    tenant_id: str,
) -> float:
    """Compute encryption percentage from findings.

    Counts distinct resource_uids that have at least one
    data_protection_encryption module finding with status='PASS'
    versus total distinct resource_uids.

    Args:
        cur: Database cursor.
        datasec_scan_id: Scan identifier.
        tenant_id: Tenant identifier.

    Returns:
        Encrypted percentage as a float (0.0 - 100.0).
    """
    try:
        cur.execute(
            """
            SELECT
                COUNT(DISTINCT resource_uid) FILTER (
                    WHERE 'data_protection_encryption' = ANY(datasec_modules)
                      AND status = 'PASS'
                ) AS encrypted,
                COUNT(DISTINCT resource_uid) AS total
            FROM datasec_findings
            WHERE datasec_scan_id = %s AND tenant_id = %s
            """,
            (datasec_scan_id, tenant_id),
        )
        row = cur.fetchone()
        if row and row["total"] > 0:
            return round(row["encrypted"] / row["total"] * 100, 1)
    except Exception:
        logger.warning("Failed to compute encrypted_pct from findings", exc_info=True)
    return 0.0


def _build_catalog(
    cur: psycopg2.extensions.cursor,
    datasec_scan_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Build a data-store catalog from findings.

    Groups findings by resource_uid for resource_types that match active
    data store services (from datasec_data_store_services table), returning
    one catalog entry per unique resource.

    Args:
        cur: Database cursor (RealDictCursor).
        datasec_scan_id: Scan identifier.
        tenant_id: Tenant identifier.

    Returns:
        List of catalog entry dicts.
    """
    try:
        # Get active data store service resource types
        cur.execute(
            """
            SELECT service_name FROM datasec_data_store_services WHERE is_active = TRUE
            """
        )
        active_services = {row["service_name"].lower() for row in cur.fetchall()}
    except Exception:
        # Table may not exist yet — fall back to common data stores
        active_services = {
            "s3", "rds", "dynamodb", "redshift", "ebs", "efs",
            "elasticsearch", "opensearch", "glue", "athena",
            "documentdb", "neptune", "aurora",
        }

    cur.execute(
        """
        SELECT resource_uid,
               resource_type,
               resource_id,
               resource_arn,
               account_id,
               region,
               data_classification,
               sensitivity_score,
               COUNT(*) AS finding_count,
               COUNT(*) FILTER (WHERE status = 'FAIL') AS fail_count,
               COUNT(*) FILTER (WHERE status = 'PASS') AS pass_count
        FROM datasec_findings
        WHERE datasec_scan_id = %s AND tenant_id = %s
        GROUP BY resource_uid, resource_type, resource_id, resource_arn,
                 account_id, region, data_classification, sensitivity_score
        ORDER BY fail_count DESC, sensitivity_score DESC NULLS LAST
        """,
        (datasec_scan_id, tenant_id),
    )
    rows = cur.fetchall()

    catalog: List[Dict[str, Any]] = []
    seen_uids: set = set()
    for row in rows:
        uid = row.get("resource_uid") or row.get("resource_id") or ""
        if uid in seen_uids:
            continue

        # Filter to data store resource types when active_services known
        rtype = (row.get("resource_type") or "").lower()
        if active_services and not any(svc in rtype for svc in active_services):
            continue

        seen_uids.add(uid)
        catalog.append({
            "resource_uid": uid,
            "resource_type": row.get("resource_type"),
            "resource_id": row.get("resource_id"),
            "resource_arn": row.get("resource_arn"),
            "account_id": row.get("account_id"),
            "region": row.get("region"),
            "data_classification": row.get("data_classification") or [],
            "sensitivity_score": row.get("sensitivity_score"),
            "finding_count": row["finding_count"],
            "fail_count": row["fail_count"],
            "pass_count": row["pass_count"],
        })

    return catalog


def _query_region_breakdown(
    cur: psycopg2.extensions.cursor,
    datasec_scan_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Compute data residency breakdown by region from datasec_findings.

    Groups findings by region, counting total findings, distinct resources,
    and fail counts per region.

    Args:
        cur: Database cursor (RealDictCursor).
        datasec_scan_id: Scan identifier.
        tenant_id: Tenant identifier.

    Returns:
        List of region breakdown dicts sorted by resource count descending.
    """
    try:
        cur.execute(
            """
            SELECT region,
                   COUNT(*) AS finding_count,
                   COUNT(DISTINCT resource_uid) AS resource_count,
                   COUNT(*) FILTER (WHERE status = 'FAIL') AS fail_count
            FROM datasec_findings
            WHERE datasec_scan_id = %s
              AND tenant_id = %s
              AND region IS NOT NULL
            GROUP BY region
            ORDER BY resource_count DESC
            """,
            (datasec_scan_id, tenant_id),
        )
        rows = cur.fetchall()
        return [
            {
                "region": row["region"],
                "finding_count": row["finding_count"],
                "resource_count": row["resource_count"],
                "fail_count": row["fail_count"],
            }
            for row in rows
        ]
    except Exception:
        logger.warning("Failed to compute region breakdown", exc_info=True)
        return []
