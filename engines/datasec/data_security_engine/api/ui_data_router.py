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


def _query_datasec_scan_trend(conn, tenant_id: str) -> list:
    """Return last 8 datasec scan summaries for trend charts (oldest-first)."""
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    to_char(created_at, 'Mon DD')     AS date,
                    COALESCE(total_findings, 0)        AS total,
                    COALESCE(critical_findings, 0)     AS critical,
                    COALESCE(high_findings, 0)         AS high,
                    COALESCE(medium_findings, 0)       AS medium,
                    COALESCE(low_findings, 0)          AS low,
                    COALESCE(data_risk_score, 0)       AS pass_rate
                FROM datasec_report
                WHERE tenant_id = %s
                ORDER BY created_at DESC
                LIMIT 8
                """,
                (tenant_id,),
            )
            return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("datasec scan_trend query failed", exc_info=True)
        return []


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
    # Try report table first (with findings)
    cur.execute(
        """
        SELECT scan_run_id
        FROM datasec_report
        WHERE tenant_id = %s AND total_findings > 0
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    if row:
        return row["scan_run_id"]
    # Fallback: find latest scan_run_id from findings directly
    cur.execute(
        """
        SELECT scan_run_id, COUNT(*) AS cnt
        FROM datasec_findings
        WHERE tenant_id = %s
        GROUP BY scan_run_id
        ORDER BY MAX(last_seen_at) DESC NULLS LAST, cnt DESC
        LIMIT 1
        """,
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


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
    * **scan_id** -- the resolved scan_run_id
    """
    conn: Optional[psycopg2.extensions.connection] = None
    try:
        conn = _get_datasec_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # ── 1. Resolve scan_id ──────────────────────────────────────
            scan_run_id: Optional[str] = None
            if scan_id == "latest":
                scan_run_id = _resolve_latest_scan_run_id(cur, tenant_id)
            else:
                scan_run_id = scan_id

            if not scan_run_id:
                return _empty_response()

            # ── 2. Report-level summary ─────────────────────────────────
            cur.execute(
                """
                SELECT total_findings,
                       datasec_relevant_findings,
                       classified_resources,
                       total_data_stores,
                       findings_by_module,
                       findings_by_status,
                       severity_breakdown,
                       classification_summary,
                       residency_summary,
                       report_data,
                       provider,
                       data_risk_score,
                       encryption_score,
                       access_score,
                       classification_score,
                       lifecycle_score,
                       residency_score,
                       monitoring_score,
                       critical_findings,
                       high_findings,
                       medium_findings,
                       low_findings,
                       encrypted_pct AS report_encrypted_pct,
                       public_data_stores,
                       sensitive_exposed
                FROM datasec_report
                WHERE scan_run_id = %s AND tenant_id = %s
                LIMIT 1
                """,
                (scan_run_id, tenant_id),
            )
            report_row = cur.fetchone()

            # ── 3. Total findings count ─────────────────────────────────
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM datasec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                """,
                (scan_run_id, tenant_id),
            )
            total_row = cur.fetchone()
            total_findings = total_row["cnt"] if total_row else 0

            # ── 4. Module breakdown from datasec_findings ───────────────
            # datasec_modules is TEXT[] — unnest to count per module
            cur.execute(
                """
                SELECT m AS module, COUNT(*) AS cnt
                FROM datasec_findings, unnest(datasec_modules) AS m
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

            # ── 5. Classification breakdown ─────────────────────────────
            # data_classification is TEXT[] on datasec_findings
            cur.execute(
                """
                SELECT c AS classification, COUNT(DISTINCT resource_uid) AS cnt
                FROM datasec_findings, unnest(data_classification) AS c
                WHERE scan_run_id = %s AND tenant_id = %s
                GROUP BY c
                ORDER BY cnt DESC
                """,
                (scan_run_id, tenant_id),
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
                WHERE scan_run_id = %s
                  AND tenant_id = %s
                  AND sensitivity_score > 70
                  AND status = 'FAIL'
                """,
                (scan_run_id, tenant_id),
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
                        cur, scan_run_id, tenant_id
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
            by_region = _query_region_breakdown(cur, scan_run_id, tenant_id)

            # If report-level residency_summary was empty, populate from
            # live region counts
            if not residency and by_region:
                residency = {"by_region": by_region}
            elif residency and by_region:
                # Merge live counts under a separate key so UI has both
                residency["by_region"] = by_region

            # ── 8b. Build data-store catalog ────────────────────────────
            catalog = _build_catalog(cur, scan_run_id, tenant_id)

            # ── 9a. Module-grouped sections for BFF ─────────────────────
            # Classifications: BFF expects {name, data_type, count, locations, confidence}
            classifications = _query_classification_summary(cur, scan_run_id, tenant_id)
            # DLP violations: BFF expects {id, type, resource, data_type, severity, action, timestamp}
            dlp_violations = _query_findings_by_module(cur, scan_run_id, tenant_id, "dlp", limit)
            # Encryption status: raw findings for encryption module
            encryption_status = _query_findings_by_module(cur, scan_run_id, tenant_id, "encryption", limit)

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
                       resource_uid,
                       account_id,
                       region,
                       data_classification,
                       sensitivity_score,
                       finding_data
                FROM datasec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
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
                    "datasec_modules": f.get("datasec_modules") or [],
                    "severity": f["severity"],
                    "status": f["status"],
                    "resource_type": f.get("resource_type"),
                    "resource_id": f.get("resource_id"),
                    "resource_uid": f.get("resource_uid"),
                    "account_id": f.get("account_id"),
                    "region": f.get("region"),
                    "data_classification": f.get("data_classification") or [],
                    "sensitivity_score": f.get("sensitivity_score"),
                    "finding_data": fd,
                    # ── Rule metadata — unpacked from finding_data JSONB ──────
                    "title":                fd.get("title") or fd.get("rule_name") or f.get("rule_id", ""),
                    "description":          fd.get("description") or fd.get("rationale") or "",
                    "remediation":          fd.get("remediation") or "",
                    "posture_category":     fd.get("posture_category") or "",
                    "domain":               fd.get("domain") or fd.get("security_domain") or "",
                    "risk_score":           fd.get("risk_score"),
                    "compliance_frameworks":fd.get("compliance_frameworks") or [],
                    "mitre_tactics":        fd.get("mitre_tactics") or [],
                    "mitre_techniques":     fd.get("mitre_techniques") or [],
                    "checked_fields":       fd.get("checked_fields"),
                    "actual_values":        fd.get("actual_values"),
                    "service":              fd.get("service") or f.get("resource_type", ""),
                    "source":               fd.get("source", "check"),
                })

        # ── 10. Build activity from datasec_access_activity ──────
        activity = _query_access_activity(cur, scan_run_id, tenant_id)

        # ── 11. Build lineage from datasec_lineage ────────────────
        lineage = _query_lineage(cur, scan_run_id, tenant_id)

        # ── 11b. Scan trend (last 8 scans, oldest-first) ─────────
        scan_trend = _query_datasec_scan_trend(conn, tenant_id)

        # ── 12. Extract scores from report ────────────────────────
        data_risk_score = 0
        module_scores = {}
        if report_row:
            data_risk_score = report_row.get("data_risk_score") or 0
            module_scores = {
                "encryption": report_row.get("encryption_score") or 0,
                "access": report_row.get("access_score") or 0,
                "classification": report_row.get("classification_score") or 0,
                "lifecycle": report_row.get("lifecycle_score") or 0,
                "residency": report_row.get("residency_score") or 0,
                "monitoring": report_row.get("monitoring_score") or 0,
            }
            # Use report-level encrypted_pct if available
            rpt_enc = report_row.get("report_encrypted_pct")
            if rpt_enc and float(rpt_enc) > 0:
                encrypted_pct = float(rpt_enc)

            # Severity counts from report
            if report_row.get("critical_findings") is not None:
                sensitive_exposed = report_row.get("sensitive_exposed") or sensitive_exposed

        return {
            "summary": {
                "total_findings": total_findings,
                "total_stores": total_data_stores,
                "by_module": by_module,
                "by_classification": by_classification,
                "by_severity": {
                    "critical": report_row.get("critical_findings", 0) if report_row else 0,
                    "high": report_row.get("high_findings", 0) if report_row else 0,
                    "medium": report_row.get("medium_findings", 0) if report_row else 0,
                    "low": report_row.get("low_findings", 0) if report_row else 0,
                },
                "by_status": report_row.get("findings_by_status", {}) if report_row else {},
                "sensitive_exposed": sensitive_exposed,
                "encrypted_pct": encrypted_pct,
                "classified_pct": classified_pct,
                "data_risk_score": data_risk_score,
                "module_scores": module_scores,
                "public_data_stores": report_row.get("public_data_stores", 0) if report_row else 0,
                "residency": residency,
                "by_region": by_region,
            },
            "catalog": catalog,
            "classifications": classifications,
            "dlp_violations": dlp_violations,
            "encryption_status": encryption_status,
            "residency": by_region,
            "activity": activity,
            "lineage": lineage,
            "findings": findings,
            "total_findings": total_findings,
            "scan_id": scan_run_id,
            "scan_trend": scan_trend,
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
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_status": {},
            "sensitive_exposed": 0,
            "encrypted_pct": 0.0,
            "classified_pct": 0.0,
            "data_risk_score": 0,
            "module_scores": {},
            "public_data_stores": 0,
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
    scan_run_id: str,
    tenant_id: str,
    module_name: str,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return findings where datasec_modules[] contains *module_name*.

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: DataSec scan identifier.
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
                   resource_type, resource_id, resource_uid, account_id,
                   region, data_classification, sensitivity_score,
                   finding_data
            FROM datasec_findings
            WHERE scan_run_id = %s
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
            (scan_run_id, tenant_id, f"%{module_name}%", limit),
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
                "resource_uid": f.get("resource_uid"),
                "account_id": f.get("account_id"),
                "region": f.get("region"),
                "data_classification": f.get("data_classification") or [],
                "sensitivity_score": f.get("sensitivity_score"),
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
    scan_run_id: str,
    tenant_id: str,
) -> float:
    """Compute encryption percentage from findings.

    Counts distinct resource_uids that have at least one
    data_protection_encryption module finding with status='PASS'
    versus total distinct resource_uids.

    Args:
        cur: Database cursor.
        scan_run_id: Scan identifier.
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
            WHERE scan_run_id = %s AND tenant_id = %s
            """,
            (scan_run_id, tenant_id),
        )
        row = cur.fetchone()
        if row and row["total"] > 0:
            return round(row["encrypted"] / row["total"] * 100, 1)
    except Exception:
        logger.warning("Failed to compute encrypted_pct from findings", exc_info=True)
    return 0.0


def _build_catalog(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Build a data-store catalog for the BFF normalize_datastore() function.

    Primary source: datasec_data_catalog (enriched with discovery metadata).
    Fallback: datasec_findings grouped by resource_uid.

    The BFF expects each entry to have:
      resource_uid, resource_type, account_id, region, provider,
      metadata.name, metadata.size_bytes, metadata.record_count,
      metadata.data_classification, metadata.encryption_status,
      metadata.public_access, tags.Owner, discovered_at
    """
    # ── Try enriched data catalog first ───────────────────────────────
    catalog_from_table = _try_enriched_catalog(cur, scan_run_id, tenant_id)
    if catalog_from_table:
        return catalog_from_table

    # ── Fallback: build from findings ─────────────────────────────────
    try:
        active_services = _load_active_services(cur)
    except Exception:
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
               account_id,
               provider,
               region,
               data_classification,
               sensitivity_score,
               COUNT(*) AS finding_count,
               COUNT(*) FILTER (WHERE status = 'FAIL') AS fail_count,
               COUNT(*) FILTER (WHERE status = 'PASS') AS pass_count
        FROM datasec_findings
        WHERE scan_run_id = %s AND tenant_id = %s
        GROUP BY resource_uid, resource_type, resource_id,
                 account_id, provider, region, data_classification, sensitivity_score
        ORDER BY fail_count DESC, sensitivity_score DESC NULLS LAST
        """,
        (scan_run_id, tenant_id),
    )
    rows = cur.fetchall()

    catalog: List[Dict[str, Any]] = []
    seen_uids: set = set()
    for row in rows:
        uid = row.get("resource_uid") or row.get("resource_id") or ""
        if uid in seen_uids:
            continue
        rtype = (row.get("resource_type") or "").lower()
        if active_services and not any(svc in rtype for svc in active_services):
            continue

        seen_uids.add(uid)
        # Shape it for BFF normalize_datastore()
        classifications = row.get("data_classification") or []
        classification_str = classifications[0] if classifications else ""

        catalog.append({
            "resource_uid": uid,
            "id": uid,
            "resource_type": row.get("resource_type"),
            "resource_id": row.get("resource_id"),
            "account_id": row.get("account_id"),
            "provider": row.get("provider", "aws"),
            "region": row.get("region"),
            "metadata": {
                "name": (row.get("resource_id") or uid).rsplit("/", 1)[-1],
                "data_classification": classification_str,
                "size_bytes": None,
                "record_count": None,
                "encryption_status": None,
                "public_access": False,
            },
            "tags": {},
            "sensitivity_score": row.get("sensitivity_score"),
            "finding_count": row["finding_count"],
            "fail_count": row["fail_count"],
            "pass_count": row["pass_count"],
        })

    return catalog


def _try_enriched_catalog(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Try to load from datasec_data_catalog (enriched with discovery metadata)."""
    try:
        cur.execute("""
            SELECT c.resource_uid, c.resource_type, c.resource_name, c.service,
                   c.account_id, c.provider, c.region,
                   c.size_bytes, c.record_count, c.owner, c.tags,
                   c.data_classification, c.sensitivity_score,
                   c.encryption_at_rest, c.kms_key_type,
                   c.is_public, c.versioning_enabled,
                   c.finding_count, c.fail_count, c.risk_score,
                   c.last_scanned_at
            FROM datasec_data_catalog c
            WHERE c.scan_run_id = %s AND c.tenant_id = %s
            ORDER BY c.fail_count DESC, c.risk_score DESC
        """, (scan_run_id, tenant_id))
        rows = cur.fetchall()

        if not rows:
            return []

        catalog = []
        for row in rows:
            uid = row.get("resource_uid", "")
            classifications = row.get("data_classification") or []
            classification_str = classifications[0] if classifications else ""

            enc_status = "Unencrypted"
            if row.get("encryption_at_rest"):
                ktype = row.get("kms_key_type", "")
                enc_status = "CMK" if "customer" in (ktype or "").lower() else "AWS-Managed"

            catalog.append({
                "resource_uid": uid,
                "id": uid,
                "resource_type": row.get("resource_type") or row.get("service", ""),
                "account_id": row.get("account_id", ""),
                "provider": row.get("provider", "aws"),
                "region": row.get("region", ""),
                "metadata": {
                    "name": row.get("resource_name") or uid.rsplit("/", 1)[-1],
                    "size_bytes": row.get("size_bytes"),
                    "record_count": row.get("record_count"),
                    "data_classification": classification_str,
                    "encryption_status": enc_status,
                    "public_access": row.get("is_public", False),
                },
                "tags": row.get("tags") or {},
                "discovered_at": row["last_scanned_at"].isoformat() if row.get("last_scanned_at") else None,
                "sensitivity_score": row.get("sensitivity_score"),
                "finding_count": row.get("finding_count", 0),
                "fail_count": row.get("fail_count", 0),
            })

        return catalog
    except Exception:
        logger.debug("datasec_data_catalog table not available, falling back to findings")
        return []


def _load_active_services(cur: psycopg2.extensions.cursor):
    """Load active data store service names."""
    cur.execute("SELECT service_name FROM datasec_data_store_services WHERE is_active = TRUE")
    return {row["service_name"].lower() for row in cur.fetchall()}


def _query_region_breakdown(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Compute data residency breakdown by region from datasec_findings.

    Groups findings by region, counting total findings, distinct resources,
    and fail counts per region.

    Args:
        cur: Database cursor (RealDictCursor).
        scan_run_id: Scan identifier.
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
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND region IS NOT NULL
            GROUP BY region
            ORDER BY resource_count DESC
            """,
            (scan_run_id, tenant_id),
        )
        rows = cur.fetchall()
        return [
            {
                "region": row["region"],
                "assets": row["resource_count"],       # BFF normalize_residency expects "assets"
                "count": row["resource_count"],         # alt key
                "finding_count": row["finding_count"],
                "resource_count": row["resource_count"],
                "fail_count": row["fail_count"],
                "status": "compliant" if row["fail_count"] == 0 else "non-compliant",
                "compliance": "compliant" if row["fail_count"] == 0 else "non-compliant",
            }
            for row in rows
        ]
    except Exception:
        logger.warning("Failed to compute region breakdown", exc_info=True)
        return []


def _query_access_activity(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Query recent data access activity from datasec_access_activity table.

    Returns an empty list if the table doesn't exist yet (graceful degradation).
    """
    try:
        cur.execute(
            """
            SELECT resource_uid, resource_type, principal, action,
                   event_time, source_ip, is_anomaly, anomaly_reason
            FROM datasec_access_activity
            WHERE tenant_id = %s
              AND (scan_run_id = %s OR scan_run_id IS NULL)
            ORDER BY event_time DESC NULLS LAST
            LIMIT %s
            """,
            (tenant_id, scan_run_id, limit),
        )
        return [
            {
                "resource": row.get("resource_uid", ""),
                "resource_type": row.get("resource_type", ""),
                "user": row.get("principal", ""),
                "action": row.get("action", ""),
                "timestamp": row["event_time"].isoformat() if row.get("event_time") else None,
                "location": row.get("source_ip", ""),
                "anomaly": row.get("is_anomaly", False),
                "anomaly_reason": row.get("anomaly_reason", ""),
            }
            for row in cur.fetchall()
        ]
    except Exception:
        # Table may not exist yet
        logger.debug("datasec_access_activity table not available")
        return []


def _query_lineage(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
    limit: int = 500,
) -> Dict[str, Any]:
    """Query data lineage (flow relationships) from datasec_lineage table.

    Returns a graph-friendly structure with nodes and edges for the UI.
    """
    try:
        cur.execute(
            """
            SELECT source_uid, source_type, source_region,
                   destination_uid, destination_type, destination_region,
                   transfer_type, is_cross_region, is_cross_account
            FROM datasec_lineage
            WHERE scan_run_id = %s AND tenant_id = %s
            ORDER BY source_uid
            LIMIT %s
            """,
            (scan_run_id, tenant_id, limit),
        )
        rows = cur.fetchall()

        if not rows:
            return {}

        nodes = {}
        edges = []
        for row in rows:
            src = row["source_uid"]
            dst = row["destination_uid"]
            if src and src not in nodes:
                nodes[src] = {
                    "id": src,
                    "type": row.get("source_type", ""),
                    "region": row.get("source_region", ""),
                }
            if dst and dst not in nodes:
                nodes[dst] = {
                    "id": dst,
                    "type": row.get("destination_type", ""),
                    "region": row.get("destination_region", ""),
                }
            edges.append({
                "source": src,
                "target": dst,
                "transfer_type": row.get("transfer_type", ""),
                "is_cross_region": row.get("is_cross_region", False),
                "is_cross_account": row.get("is_cross_account", False),
            })

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "total_flows": len(edges),
            "cross_region_flows": sum(1 for e in edges if e.get("is_cross_region")),
        }
    except Exception:
        logger.debug("datasec_lineage table not available")
        return {}


def _query_classification_summary(
    cur: psycopg2.extensions.cursor,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """Build classification summary for BFF normalize_classification().

    BFF expects: {name|pattern_name, data_type|classification, count|total,
                  locations, confidence, auto_classified}

    We build this from the data_classification TEXT[] on datasec_findings,
    counting how many distinct resources have each classification type.
    """
    try:
        cur.execute(
            """
            SELECT c AS classification_type,
                   COUNT(DISTINCT resource_uid) AS resource_count,
                   COUNT(*) AS finding_count,
                   array_agg(DISTINCT region) FILTER (WHERE region IS NOT NULL) AS regions
            FROM datasec_findings, unnest(data_classification) AS c
            WHERE scan_run_id = %s AND tenant_id = %s
            GROUP BY c
            ORDER BY resource_count DESC
            """,
            (scan_run_id, tenant_id),
        )
        rows = cur.fetchall()

        return [
            {
                "name": row["classification_type"],
                "pattern_name": row["classification_type"],
                "data_type": row["classification_type"],
                "classification": row["classification_type"],
                "count": row["resource_count"],
                "total": row["finding_count"],
                "locations": row.get("regions") or [],
                "confidence": 0.85,         # default confidence for rule-based classification
                "auto_classified": True,
            }
            for row in rows
        ]
    except Exception:
        logger.warning("Failed to build classification summary", exc_info=True)
        return []
