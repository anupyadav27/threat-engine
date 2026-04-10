"""
Dependency and Blast Radius API endpoints.

GET /api/v1/encryption/keys/{key_id}/dependencies
GET /api/v1/encryption/keys/{key_id}/blast-radius
GET /api/v1/encryption/blast-radius/summary
GET /api/v1/encryption/remediations
"""

import logging
import os
import json
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, Query, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dependencies"])


def _get_encryption_conn():
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


def _resolve_latest_scan(cur, tenant_id: str) -> Optional[str]:
    cur.execute(
        """SELECT scan_run_id FROM encryption_report
           WHERE tenant_id = %s AND status = 'completed'
           ORDER BY generated_at DESC LIMIT 1""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return row["scan_run_id"] if row else None


@router.get("/api/v1/encryption/keys/{key_id}/dependencies")
async def get_key_dependencies(
    key_id: str,
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
) -> Dict[str, Any]:
    """Get all resources that depend on a KMS key."""
    conn = None
    try:
        conn = _get_encryption_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                raise HTTPException(status_code=404, detail="No completed scan found")

            # Find the key in inventory
            cur.execute(
                """SELECT key_arn, key_id, key_alias, key_state, key_manager,
                          dependent_resource_count, account_id, region
                   FROM encryption_key_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                     AND (key_arn LIKE %s OR key_id = %s)
                   LIMIT 1""",
                (scan_run_id, tenant_id, f"%{key_id}%", key_id),
            )
            key_row = cur.fetchone()
            if not key_row:
                raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

            key_arn = key_row["key_arn"]

            # Find dependent resources from findings that reference this key
            cur.execute(
                """SELECT resource_uid, resource_type, region, account_id,
                          encryption_status, severity, status, finding_data
                   FROM encryption_findings
                   WHERE scan_run_id = %s AND tenant_id = %s
                     AND finding_data::text LIKE %s
                   ORDER BY severity""",
                (scan_run_id, tenant_id, f"%{key_id}%"),
            )
            deps = []
            for r in cur.fetchall():
                fd = r.get("finding_data")
                if not isinstance(fd, dict):
                    fd = {}
                deps.append({**dict(r), "finding_data": fd})

            # Also check report_data for dependency graph
            cur.execute(
                "SELECT report_data FROM encryption_report WHERE scan_run_id = %s",
                (scan_run_id,),
            )
            report = cur.fetchone()
            dep_graph = {}
            if report and isinstance(report.get("report_data"), dict):
                dep_graph = report["report_data"].get("dependency_graph", {})

            # Get graph-based dependencies
            graph_deps = dep_graph.get("key_to_resources", {}).get(key_arn, [])

        return {
            "key": dict(key_row),
            "dependencies": deps,
            "graph_dependencies": graph_deps,
            "total_dependencies": max(len(deps), len(graph_deps)),
            "scan_id": scan_run_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error fetching key dependencies")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()


@router.get("/api/v1/encryption/keys/{key_id}/blast-radius")
async def get_key_blast_radius(
    key_id: str,
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
) -> Dict[str, Any]:
    """Get blast radius analysis for a KMS key."""
    conn = None
    try:
        conn = _get_encryption_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                raise HTTPException(status_code=404, detail="No completed scan found")

            # Get blast radius from report_data
            cur.execute(
                "SELECT report_data FROM encryption_report WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            if not report:
                raise HTTPException(status_code=404, detail="Report not found")

            report_data = report.get("report_data") or {}
            if not isinstance(report_data, dict):
                report_data = {}

            blast_radii = report_data.get("blast_radii", [])

            # Find the specific key
            for br in blast_radii:
                if key_id in (br.get("key_arn", "") or "") or key_id == br.get("key_metadata", {}).get("key_id"):
                    return {**br, "scan_id": scan_run_id}

            # If not pre-computed, return basic info
            cur.execute(
                """SELECT key_arn, key_id, key_alias, key_state, key_manager,
                          dependent_resource_count, account_id, region
                   FROM encryption_key_inventory
                   WHERE scan_run_id = %s AND tenant_id = %s
                     AND (key_arn LIKE %s OR key_id = %s)
                   LIMIT 1""",
                (scan_run_id, tenant_id, f"%{key_id}%", key_id),
            )
            key_row = cur.fetchone()
            if not key_row:
                raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

            return {
                "key_arn": key_row["key_arn"],
                "key_metadata": dict(key_row),
                "total_affected": key_row.get("dependent_resource_count", 0),
                "blast_radius_score": 0,
                "severity": "UNKNOWN",
                "affected_resources": [],
                "message": "Blast radius not yet computed — run a full scan",
                "scan_id": scan_run_id,
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error fetching blast radius")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()


@router.get("/api/v1/encryption/blast-radius/summary")
async def get_blast_radius_summary(
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
) -> Dict[str, Any]:
    """Get blast radius summary for all keys."""
    conn = None
    try:
        conn = _get_encryption_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return {"blast_radii": [], "scan_id": None}

            cur.execute(
                "SELECT report_data FROM encryption_report WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            report_data = (report.get("report_data") or {}) if report else {}
            if not isinstance(report_data, dict):
                report_data = {}

            blast_radii = report_data.get("blast_radii", [])

            # Return summary view (without full affected_resources lists)
            summary = []
            for br in blast_radii:
                summary.append({
                    "key_arn": br.get("key_arn"),
                    "key_metadata": br.get("key_metadata", {}),
                    "total_affected": br.get("total_affected", 0),
                    "blast_radius_score": br.get("blast_radius_score", 0),
                    "severity": br.get("severity"),
                    "by_severity": br.get("by_severity", {}),
                    "by_type": br.get("by_type", {}),
                })

        return {"blast_radii": summary, "scan_id": scan_run_id}
    except Exception as e:
        logger.exception("Error fetching blast radius summary")
        return {"blast_radii": [], "scan_id": None, "error": str(e)}
    finally:
        if conn:
            conn.close()


@router.get("/api/v1/encryption/remediations")
async def get_remediations(
    tenant_id: str = Query(...),
    scan_id: str = Query(default="latest"),
    top_n: int = Query(default=10, ge=1, le=50),
) -> Dict[str, Any]:
    """Get top-priority remediation recommendations."""
    conn = None
    try:
        conn = _get_encryption_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scan_run_id = _resolve_latest_scan(cur, tenant_id) if scan_id == "latest" else scan_id
            if not scan_run_id:
                return {"remediations": [], "scan_id": None}

            cur.execute(
                "SELECT report_data FROM encryption_report WHERE scan_run_id = %s AND tenant_id = %s",
                (scan_run_id, tenant_id),
            )
            report = cur.fetchone()
            report_data = (report.get("report_data") or {}) if report else {}
            if not isinstance(report_data, dict):
                report_data = {}

            remediations = report_data.get("top_remediations", [])[:top_n]

        return {"remediations": remediations, "scan_id": scan_run_id}
    except Exception as e:
        logger.exception("Error fetching remediations")
        return {"remediations": [], "scan_id": None, "error": str(e)}
    finally:
        if conn:
            conn.close()
